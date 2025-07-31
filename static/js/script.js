// static/js/script.js
console.log("Script de inventario cargado.");

// Puedes añadir más funcionalidades aquí a medida que las necesites.
// Por ejemplo, validaciones de formulario del lado del cliente,
// confirmaciones antes de borrar, etc.

// Ejemplo: Añadir una confirmación simple al botón de guardar del formulario
document.addEventListener('DOMContentLoaded', function() {
    const addItemForm = document.getElementById('addItemForm'); // Asegúrate de que tu form tenga id="addItemForm"

    if (addItemForm) {
        addItemForm.addEventListener('submit', function(event) {
            // Puedes añadir validaciones aquí antes de confirmar

            // Confirmación simple (opcional)
            /*
            const confirmed = confirm('¿Estás seguro de que quieres guardar este objeto?');
            if (!confirmed) {
                event.preventDefault(); // Cancela el envío del formulario si el usuario dice "Cancelar"
                console.log('Envío cancelado por el usuario.');
            } else {
                console.log('Enviando formulario...');
                // Podrías deshabilitar el botón para evitar doble envío aquí
                // event.target.querySelector('button[type=submit]').disabled = true;
            }
            */
           console.log('Procesando envío de formulario...');
           // Por ahora solo log, la confirmación puede ser molesta sin lógica AJAX
        });
    }
});