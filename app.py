import os
import uuid
import barcode
from barcode.writer import ImageWriter
from datetime import datetime, timezone
import logging
import pytz
import psycopg
from psycopg.rows import dict_row
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, g, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv


load_dotenv()


# --- Configuración básica de logging ---
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)


app.secret_key = os.environ.get("FLASK_SECRET_KEY")


DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    logging.critical("Error: La variable de entorno DATABASE_URL no está configurada.")


# --- Definir Zona Horaria ---
try:
    PANAMA_TZ = pytz.timezone('America/Panama')
except pytz.UnknownTimeZoneError:
    logging.warning("Zona horaria 'America/Panama' no encontrada, usando UTC.")
    PANAMA_TZ = timezone.utc


# --- Gestión de la Conexión a la Base de Datos ---
def get_db_connection():
    """Crea y devuelve una conexión a la base de datos."""
    try:
        # Usa dict_row para que las consultas devuelvan diccionarios en lugar de tuplas.
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return conn
    except psycopg.OperationalError as e:
        logging.error(f"No se pudo conectar a la base de datos PostgreSQL: {e}")
        return None



# --- Context Processor (sin cambios) ---
@app.context_processor
def inject_now():
    now_panama = datetime.now(PANAMA_TZ)
    return {
        'now': now_panama,
        'current_date': now_panama.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    }


# --- Helper para borrar barcode (sin cambios) ---
def delete_barcode_image(barcode_url):
    """Intenta eliminar un archivo de código de barras basado en su URL relativa."""
    if not barcode_url:
        logging.warning("Se intentó borrar barcode pero la URL estaba vacía.")
        return False
    relative_static_path = url_for('static', filename='barcode/')
    if not barcode_url.startswith(relative_static_path):
        logging.warning(f"URL de barcode no parece ser una ruta estática válida: {barcode_url}")
        return False
    try:
        filename = os.path.basename(barcode_url)
        filepath = os.path.join('static', 'barcode', filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            logging.info(f"Archivo de código de barras eliminado: {filepath}")
            return True
        else:
            logging.warning(f"No se encontró el archivo de código de barras para eliminar: {filepath}")
            return False
    except Exception as e:
        logging.error(f"Error al intentar eliminar el archivo desde URL {barcode_url}: {e}", exc_info=True)
        return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, inicia sesión para acceder a esta página.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("No tienes permiso para acceder a esta página.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# --- FUNCIÓN DE AUDITORÍA ---
def log_action(action, target_id=None, details=None):
    """Registra una acción en la tabla user_actions."""
    user_id = session.get('user_id')
    username = session.get('username')
    if not user_id:
        return  # No registrar si no hay usuario en sesión

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO user_actions (user_id, username, action, target_id, details)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cur.execute(sql, (user_id, username, action, target_id, details))
                conn.commit()
    except psycopg.Error as e:
        logging.error(f"Error al registrar la acción '{action}': {e}")


# --- RUTAS DE AUTENTICACIÓN ---

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")

        if not username or not password:
            flash("El nombre de usuario y la contraseña son obligatorios.", "warning")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    # Comprobar si ya existe el usuario
                    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                    if cur.fetchone():
                        flash("El nombre de usuario ya existe. Por favor, elige otro.", "warning")
                        return render_template("register.html")

                    # Comprobar si es el primer usuario para hacerlo admin
                    cur.execute("SELECT id FROM users LIMIT 1")
                    is_first_user = cur.fetchone() is None

                    role = 'admin' if is_first_user else 'viewer'
                    is_approved = True if is_first_user else False

                    sql = "INSERT INTO users (username, password_hash, role, is_approved) VALUES (%s, %s, %s, %s)"
                    cur.execute(sql, (username, password_hash, role, is_approved))
                    conn.commit()

                    if is_first_user:
                        flash(
                            "¡Registro exitoso! Eres el primer usuario, se te ha asignado el rol de Administrador. Ya puedes iniciar sesión.",
                            "success")
                        return redirect(url_for('login'))
                    else:
                        flash(
                            "¡Registro exitoso! Tu cuenta ha sido creada y está pendiente de aprobación por un administrador.",
                            "info")
                        return redirect(url_for('login'))

        except psycopg.Error as e:
            flash("Error en la base de datos al registrar el usuario.", "danger")
            logging.error(f"Error en registro: {e}")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cur.fetchone()

                if user and check_password_hash(user['password_hash'], password):
                    if not user['is_approved']:
                        flash("Tu cuenta aún no ha sido aprobada por un administrador.", "warning")
                        return redirect(url_for('login'))

                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    flash(f"¡Bienvenido de nuevo, {user['username']}!", "success")
                    log_action('USER_LOGIN')
                    return redirect(url_for('dashboard'))
                else:
                    flash("Nombre de usuario o contraseña incorrectos.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_action('USER_LOGOUT')
    session.clear()
    flash("Has cerrado sesión.", "info")
    return redirect(url_for('login'))


# --- Rutas de la Aplicación ---

@app.route("/")
@login_required
def dashboard():
    """ Muestra el dashboard con inventario y permite buscar por ID. """
    search_query = request.args.get('search_id', '').strip()
    items = []

    try:
        with get_db_connection() as conn:
            if conn is None:
                raise psycopg.OperationalError("No se pudo establecer la conexión a la base de datos.")

            with conn.cursor() as cur:
                if search_query:
                    # Búsqueda mejorada por ID, objeto o marca
                    sql_query = "SELECT * FROM items WHERE id ILIKE %s OR objeto ILIKE %s OR marca ILIKE %s ORDER BY fecha_ingreso DESC"
                    search_term = f"%{search_query}%"
                    cur.execute(sql_query, (search_term, search_term, search_term))
                else:
                    sql_query = "SELECT * FROM items ORDER BY fecha_ingreso DESC"
                    cur.execute(sql_query)

                items = cur.fetchall()

                if search_query and not items:
                    flash(f"No se encontró ningún objeto con el ID '{search_query}'.", "warning")
                elif search_query and items:
                    flash(f"Mostrando resultados para el ID '{search_query}'.", "info")

                # Formatear fechas para visualización
                for item in items:
                    fecha_ingreso_utc = item['fecha_ingreso']
                    if isinstance(fecha_ingreso_utc, datetime):
                        item['fecha_ingreso_str'] = fecha_ingreso_utc.astimezone(PANAMA_TZ).strftime("%Y-%m-%d %H:%M")
                    else:
                        item['fecha_ingreso_str'] = 'Fecha inválida'

    except psycopg.Error as e:
        logging.error(f"Error de base de datos al obtener datos para el dashboard: {e}", exc_info=True)
        flash("Error al cargar los datos del inventario desde la base de datos.", "danger")
    except Exception as e:
        logging.error(f"Error inesperado en el dashboard: {e}", exc_info=True)
        flash("Ocurrió un error inesperado al cargar la página.", "danger")

    return render_template("dashboard.html", items=items, search_query=search_query)


@app.route("/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_item():

    if request.method == "POST":
        try:

            objeto = request.form.get("objeto", "").strip()
            color = request.form.get("color", "").strip()
            material = request.form.get("material", "").strip()
            marca = request.form.get("marca", "").strip()
            detalle = request.form.get("detalle", "").strip()
            pertenece = request.form.get("pertenece", "").strip()
            lugar = request.form.get("lugar", "").strip()

            if not all([objeto, pertenece, lugar]):
                flash("Error: Faltan campos obligatorios (objeto, pertenece, lugar).", "warning")
                return render_template("add_item.html", form_data=request.form), 400

            id_objeto = str(uuid.uuid4())[:8]

            # --- Generar Código de Barras ---
            barcode_filename = f"{id_objeto}.png"
            barcode_folder = os.path.join('static', 'barcode')
            os.makedirs(barcode_folder, exist_ok=True)
            barcode_path_full = os.path.join(barcode_folder, barcode_filename)
            barcode_url = url_for('static', filename=f'barcode/{barcode_filename}')

            try:
                code128 = barcode.get('code128', id_objeto, writer=ImageWriter())
                code128.save(os.path.join(barcode_folder, id_objeto))
            except Exception as e_barcode:
                logging.error(f"Error generando/guardando barcode para ID {id_objeto}: {e_barcode}", exc_info=True)
                flash("Error interno al generar el código de barras.", "danger")
                return render_template("add_item.html", form_data=request.form), 500

            # --- Guardar en PostgreSQL ---
            with get_db_connection() as conn:
                if conn is None:
                    raise psycopg.OperationalError("No se pudo conectar a la base de datos.")

                with conn.cursor() as cur:
                    sql_insert = """
                        INSERT INTO items (id, objeto, color, material, marca, detalle, lugar, pertenece_a, fecha_ingreso, extraido_por, codigo_barras_url)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    # Usamos datetime.now(timezone.utc) para consistencia
                    cur.execute(sql_insert, (
                        id_objeto, objeto, color, material, marca, detalle, lugar, pertenece,
                        datetime.now(timezone.utc), "manual", barcode_url
                    ))
                    conn.commit()

            logging.info(f"Objeto insertado con ID: {id_objeto}")
            flash(f"¡Objeto '{objeto}' añadido con éxito!", "success")
            return redirect(url_for('dashboard'))

        except psycopg.Error as e_db:
            logging.error(f"Error de base de datos al insertar: {e_db}", exc_info=True)
            delete_barcode_image(barcode_url)  # Intentar borrar barcode si falla la inserción
            flash("Error al guardar en la base de datos.", "danger")
            return render_template("add_item.html", form_data=request.form), 500
        except Exception as e_general:
            logging.error(f"Error general en POST /add: {e_general}", exc_info=True)
            flash("Ocurrió un error inesperado procesando la solicitud.", "danger")
            return render_template("add_item.html", form_data=request.form), 500

    return render_template("add_item.html", form_data={})


@app.route("/edit/<item_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_item(item_id):

    if request.method == "POST":
        try:
            # Obtener datos del formulario
            objeto = request.form.get("objeto", "").strip()
            color = request.form.get("color", "").strip()
            material = request.form.get("material", "").strip()
            marca = request.form.get("marca", "").strip()
            detalle = request.form.get("detalle", "").strip()
            pertenece_a = request.form.get("pertenece", "").strip()
            lugar = request.form.get("lugar", "").strip()

            if not all([objeto, pertenece_a, lugar]):
                flash("Error: Faltan campos obligatorios (objeto, pertenece a, lugar).", "warning")
                # Preparamos los datos para reenviar al formulario
                item_for_template = request.form.to_dict()
                item_for_template['id'] = item_id
                # Necesitamos recuperar la URL del código de barras
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT codigo_barras_url, fecha_ingreso FROM items WHERE id = %s", (item_id,))
                        original_item = cur.fetchone()
                        if original_item:
                            item_for_template['codigo_barras_url'] = original_item['codigo_barras_url']
                            item_for_template['fecha_ingreso_str'] = original_item['fecha_ingreso'].astimezone(
                                PANAMA_TZ).strftime("%Y-%m-%d %H:%M")
                return render_template("edit_item.html", item=item_for_template), 400

            # Actualizar en PostgreSQL
            with get_db_connection() as conn:
                if conn is None:
                    raise psycopg.OperationalError("No se pudo conectar a la base de datos.")

                with conn.cursor() as cur:
                    sql_update = """
                        UPDATE items
                        SET objeto = %s, color = %s, material = %s, marca = %s,
                            detalle = %s, pertenece_a = %s, lugar = %s,
                            fecha_modificacion = %s
                        WHERE id = %s
                    """
                    cur.execute(sql_update, (
                        objeto, color, material, marca, detalle, pertenece_a, lugar,
                        datetime.now(timezone.utc), item_id
                    ))
                    conn.commit()

                    if cur.rowcount == 0:
                        flash(f"Error: No se encontró el objeto con ID {item_id} para actualizar.", "warning")
                        return redirect(url_for('dashboard'))
                    else:
                        flash(f"Objeto '{objeto}' (ID: {item_id}) actualizado con éxito.", "success")

            return redirect(url_for('dashboard'))

        except psycopg.Error as e:
            logging.error(f"Error de base de datos en POST /edit/{item_id}: {e}", exc_info=True)
            flash("Ocurrió un error al intentar actualizar el objeto en la base de datos.", "danger")
            return redirect(url_for('edit_item', item_id=item_id))
        except Exception as e:
            logging.error(f"Error general en POST /edit/{item_id}: {e}", exc_info=True)
            flash("Ocurrió un error inesperado al actualizar el objeto.", "danger")
            return redirect(url_for('edit_item', item_id=item_id))

    # --- Manejar solicitud GET ---
    try:
        with get_db_connection() as conn:
            if conn is None:
                raise psycopg.OperationalError("No se pudo conectar a la base de datos.")

            with conn.cursor() as cur:
                cur.execute("SELECT * FROM items WHERE id = %s", (item_id,))
                item = cur.fetchone()

        if not item:
            logging.warning(f"Intento de editar item no existente: ID {item_id}")
            abort(404)

        # Formatear fechas para mostrar en el formulario
        item['fecha_ingreso_str'] = item['fecha_ingreso'].astimezone(PANAMA_TZ).strftime("%Y-%m-%d %H:%M")
        if item.get('fecha_modificacion'):
            item['fecha_modificacion_str'] = item['fecha_modificacion'].astimezone(PANAMA_TZ).strftime("%Y-%m-%d %H:%M")

        return render_template("edit_item.html", item=item)

    except psycopg.Error as e:
        logging.error(f"Error de base de datos en GET /edit/{item_id}: {e}", exc_info=True)
        flash("Error al cargar los datos del objeto para editar.", "danger")
        return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error(f"Error general en GET /edit/{item_id}: {e}", exc_info=True)
        flash("Ocurrió un error inesperado al cargar la página de edición.", "danger")
        return redirect(url_for('dashboard'))


@app.route("/delete/<item_id>", methods=["POST"])
@login_required
@admin_required
def delete_item(item_id):

    item_to_delete = None
    try:
        # Primero, obtenemos los datos del item para saber qué archivo de imagen borrar.
        with get_db_connection() as conn:
            if conn is None:
                raise psycopg.OperationalError("No se pudo conectar a la base de datos.")

            with conn.cursor() as cur:
                cur.execute("SELECT objeto, codigo_barras_url FROM items WHERE id = %s", (item_id,))
                item_to_delete = cur.fetchone()

                if not item_to_delete:
                    flash(f"Error: No se encontró el objeto con ID {item_id} para eliminar.", "warning")
                    return redirect(url_for('dashboard'))

                # Ahora, lo eliminamos
                cur.execute("DELETE FROM items WHERE id = %s", (item_id,))
                conn.commit()

                if cur.rowcount == 1:
                    flash(f"Objeto '{item_to_delete['objeto']}' (ID: {item_id}) eliminado con éxito.", "success")
                    logging.info(f"Objeto con ID {item_id} eliminado de PostgreSQL.")
                    if item_to_delete.get('codigo_barras_url'):
                        delete_barcode_image(item_to_delete['codigo_barras_url'])
                else:
                    flash(f"Error: No se pudo eliminar el objeto con ID {item_id}.", "danger")

    except psycopg.Error as e:
        logging.error(f"Error de base de datos en POST /delete/{item_id}: {e}", exc_info=True)
        flash("Ocurrió un error de base de datos al intentar eliminar el objeto.", "danger")
    except Exception as e:
        logging.error(f"Error general en POST /delete/{item_id}: {e}", exc_info=True)
        flash("Ocurrió un error inesperado al intentar eliminar el objeto.", "danger")

    return redirect(url_for('dashboard'))

@app.route("/control_panel")
@login_required
@admin_required
def control_panel():
    actions = []
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM user_actions ORDER BY timestamp DESC LIMIT 100")
                actions = cur.fetchall()
                for action in actions:
                    action['timestamp_str'] = action['timestamp'].astimezone(PANAMA_TZ).strftime("%Y-%m-%d %H:%M:%S")
    except psycopg.Error as e:
        flash("No se pudo cargar el panel de control.", "danger")
        logging.error(f"Error en panel de control: {e}")
    return render_template("control_panel.html", actions=actions)


@app.route("/admin/users")
@login_required
@admin_required
def approve_users():
    
    pending_users = []
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, created_at FROM users WHERE is_approved = FALSE ORDER BY created_at ASC")
                pending_users = cur.fetchall()
                for user in pending_users:
                    user['created_at_str'] = user['created_at'].astimezone(PANAMA_TZ).strftime("%Y-%m-%d %H:%M")
    except psycopg.Error as e:
        flash("No se pudo cargar la lista de usuarios pendientes.", "danger")
        logging.error(f"Error en approve_users: {e}")
    return render_template("approve_users.html", users=pending_users)
@app.route("/admin/approve/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def approve_user(user_id):
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_approved = TRUE WHERE id = %s RETURNING username", (user_id,))
                approved_user = cur.fetchone()
                conn.commit()
                if approved_user:
                    log_action('APPROVE_USER', target_id=user_id, details=f"Usuario: {approved_user['username']}")
                    flash(f"Usuario '{approved_user['username']}' aprobado con éxito.", "success")
                else:
                    flash("No se encontró el usuario para aprobar.", "warning")
    except psycopg.Error as e:
        flash("Error de base de datos al aprobar usuario.", "danger")
        logging.error(f"Error al aprobar usuario {user_id}: {e}")
    return redirect(url_for('approve_users'))

# --- NUEVA RUTA PARA DENEGAR USUARIOS ---
@app.route("/admin/deny/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def deny_user(user_id):
    """Elimina un registro de usuario pendiente de aprobación."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Primero, obtenemos el nombre de usuario para el registro de auditoría
                cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                user_to_deny = cur.fetchone()

                if not user_to_deny:
                    flash("No se encontró el usuario para denegar.", "warning")
                    return redirect(url_for('approve_users'))

                username = user_to_deny['username']

                # Ahora, eliminamos al usuario
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()

                log_action('DENY_USER', target_id=user_id, details=f"Usuario: {username}")
                flash(f"La solicitud del usuario '{username}' ha sido denegada y eliminada.", "info")

    except psycopg.Error as e:
        flash("Error de base de datos al denegar al usuario.", "danger")
        logging.error(f"Error al denegar usuario {user_id}: {e}")

    return redirect(url_for('approve_users'))

@app.route("/admin/manage_users")
@login_required
@admin_required
def manage_users():
    users = []
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Excluir al usuario actual de la lista para que no se pueda cambiar su propio rol
                cur.execute("SELECT id, username, role FROM users WHERE id != %s ORDER BY username", (session.get('user_id'),))
                users = cur.fetchall()
    except psycopg.Error as e:
        flash("No se pudo cargar la lista de usuarios.", "danger")
        logging.error(f"Error en manage_users: {e}")
    return render_template("manage_users.html", users=users)

@app.route("/admin/set_role/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def set_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['admin', 'viewer']:
        flash("Rol no válido.", "danger")
        return redirect(url_for('manage_users'))

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Prevenir que un admin se quite su propio rol accidentalmente desde esta ruta
                if user_id == session.get('user_id'):
                    flash("No puedes cambiar tu propio rol.", "warning")
                    return redirect(url_for('manage_users'))

                cur.execute("UPDATE users SET role = %s WHERE id = %s RETURNING username", (new_role, user_id))
                updated_user = cur.fetchone()
                conn.commit()

                if updated_user:
                    details = f"Rol del usuario '{updated_user['username']}' cambiado a '{new_role}'"
                    log_action('SET_USER_ROLE', target_id=user_id, details=details)
                    flash(f"Rol de '{updated_user['username']}' actualizado a '{new_role}'.", "success")
                else:
                    flash("Usuario no encontrado.", "warning")
    except psycopg.Error as e:
        flash("Error de base de datos al cambiar el rol.", "danger")
        logging.error(f"Error al cambiar rol para usuario {user_id}: {e}")

    return redirect(url_for('manage_users'))



# --- Manejadores de Errores (sin cambios) ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error_templates/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Error 500 interno capturado por manejador: {e}", exc_info=True)
    return render_template('error_templates/500.html', error=e), 500


# --- Ejecución (sin cambios) ---
if __name__ == "__main__":
    if not DATABASE_URL:
        print("CRÍTICO: La variable de entorno DATABASE_URL no está configurada. La aplicación no puede iniciar.")
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)