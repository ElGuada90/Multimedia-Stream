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
