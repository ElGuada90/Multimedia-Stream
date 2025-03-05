 // JavaScript para cambiar la visibilidad de la contraseña
document.getElementById('show-password').addEventListener('change', function () {
    const passwordField = document.getElementById('password-field');
    if (this.checked) {
        passwordField.type = 'text';
    } else {
        passwordField.type = 'password';
    }
});

// Al hacer clic en el enlace, enviar el formulario
document.getElementById('submit-btn').addEventListener('click', function(e) {
    e.preventDefault();  // Prevenir que se haga la acción por defecto del enlace (navegar)
    
    // Enviar el formulario
    document.getElementById('login-form').submit();
});

/// FORMULARIO OFFCANVAS
/////////////////////////////////////////////////////////////////////////////////////////////////
document.addEventListener('DOMContentLoaded', function() {
    const filasUsuario = document.querySelectorAll('.fila-usuario');
    filasUsuario.forEach(fila => {
        fila.addEventListener('click', function() {
            const idUsuario = this.getAttribute('data-usuario-id');
            const usuario = this.querySelectorAll('td');

            document.getElementById('id_usuario').value = idUsuario;
            document.getElementById('usuario').value = usuario[1].textContent;
            document.getElementById('nombre').value = usuario[2].textContent;
            document.getElementById('apellido').value = usuario[3].textContent;
            document.getElementById('email').value = usuario[4].textContent;
            document.getElementById('rol').value = usuario[5].textContent;
            document.getElementById('estado').value = usuario[6].textContent === 'Activo' ? '1' : '0';

            const offcanvasEditar = new bootstrap.Offcanvas(document.getElementById('offcanvasEditarUsuario'));
            offcanvasEditar.show();
        });
    });
});