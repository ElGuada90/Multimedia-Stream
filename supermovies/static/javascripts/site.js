 // JavaScript para cambiar la visibilidad de la contraseña
document.getElementById('show-password').addEventListener('change', function () {
    const passwordField = document.getElementById('password-field');
    if (this.checked) {
        passwordField.type = 'text';
    } else {
        passwordField.type = 'password';
    }
});
