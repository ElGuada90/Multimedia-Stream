from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from functools import wraps
from datetime import datetime, timedelta
from supermovies import app
import os

password = ""
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')

# Middleware para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para acceder a esta página.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar si el usuario tiene un rol específico
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Debes iniciar sesión para acceder a esta página.', 'error')
                return redirect(url_for('login'))
            if session.get('role') != required_role:
                flash('No tienes permiso para acceder a esta página.', 'error')
                return redirect(url_for('series'))  # Redirigir a una página sin restricciones
            return f(*args, **kwargs)
        return decorated_function
    return decorator

##################### CONTROLADOR DE INDEX
@app.route('/')
@app.route('/home')
def home():
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "index.html",
        title = "EG90  Home",
        message = "Top Stream ",
        content =  formatted_now)  

    
# Configuración de la base de datos MySQL
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = password
app.config['MYSQL_DB'] = 'multimedia'
app.config['MYSQL_HOST'] = 'localhost'
mysql = MySQL(app)

# Ruta para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    if request.method == 'POST':
        usuario = request.form['Usuario']
        contraseña = request.form['Contraseña']
        
         # Conectar y usar DictCursor
        cursor = mysql.connection.cursor(DictCursor)
        cursor.execute("SELECT * FROM Usuarios WHERE Usuario = %s", (usuario,))
        user = cursor.fetchone()
        
        if user:
            # Verificar contraseña y estado del usuario
            stored_password_hash = user['Contraseña']
            is_account_blocked = user['Estado']  # Cambiar 'Estado' según el nombre real en tu base de datos

            if check_password_hash(stored_password_hash, contraseña):
                if not is_account_blocked:  # Verificar si la cuenta está activa
                    # Guardar datos en la sesión
                    session['user_id'] = user['ID_Usuario']
                    session['username'] = user['Usuario']
                    session['role'] = user['Rol']
                    session.permanent = True  # Activar sesión persistente
                    app.permanent_session_lifetime = timedelta(days=7)  # Duración de la sesión
                    
                     # Registrar la acción de login
                    user_id = session.get('user_id')
                    user_name = session.get('username')
                    accion = f"Inicio de sesión exitoso: {user_name}"
                    cursor = mysql.connection.cursor()
                    cursor.execute(
                        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
                        (user_id, accion)
                    )
                    mysql.connection.commit()
                    
                    flash('Inicio de sesión exitoso', 'success')
                    return redirect(url_for('series'))
                else:
                    flash('Tu cuenta está bloqueada. Contacta al administrador.', 'error')
            else:
                flash('Contraseña incorrecta', 'error')
        else:
            flash('Usuario no encontrado', 'error')
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template("login.html", title="EG90 Login", message="Top Series", content=formatted_now)

# Ruta para registro de usuario
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        now = datetime.now()
        formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")
        Fecha = formatted_now
        Usuario = request.form['Usuario']
        Contraseña = request.form['Contraseña']
        Nombre = request.form['Nombre']
        Apellido = request.form['Apellido']
        Email = request.form['Email']
         # Hashear la contraseña antes de guardarla
        hashed_password = generate_password_hash(Contraseña, method='pbkdf2:sha256')
        Role = 'User'
        
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO Usuarios (Fecha, Usuario, Contraseña, Nombre, Apellido, Email, Rol) VALUES (%s, %s, %s, %s, %s, %s, %s )",
                       (Fecha, Usuario, hashed_password, Nombre, Apellido, Email, Role))
        mysql.connection.commit()
        flash('Usuario registrado exitosamente')
        return redirect(url_for('login'))
    return render_template("registro.html")

# Ruta para ver y gestionar usuarios
@app.route('/usuarios')
@role_required('Admin')
def usuarios():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template("usuarios.html", usuarios=usuarios, content = formatted_now)


# Ruta para bloquear/desbloquear usuario
@app.route('/bloquear/<int:id>')
def bloquear(id):
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET Estado = CASE WHEN Estado = 0 THEN 1 ELSE 0 END WHERE Id_Usuario = %s",  (id,) )
    conn.commit()
    flash('Estado de bloqueo cambiado')
     # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Se { 'bloqueó' if cursor.rowcount > 0 else 'desbloqueó' } la cuenta del usuario: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    return redirect(url_for('usuarios'))

# Restriccion de uauario por Bloqueo de cuenta
@app.before_request
def verificar_estado_usuario():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')

    if user_id:
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("SELECT Estado FROM usuarios WHERE Id_Usuario = %s", (user_id,))
        estado = cursor.fetchone()

        if estado and estado[0] == 1:  # Si el estado es 0, significa que está bloqueado
            flash('Tu cuenta está bloqueada. No tienes acceso a esta aplicación.')
            session.clear()  # Limpiar la sesión
            return redirect(url_for('login'))  # Redirigir a la página de login



# Ruta para ver historial
@app.route('/historial')
@role_required('Admin')
def historial():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM historial ORDER BY Fecha DESC")
    historial = cursor.fetchall()
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template("historial.html", historial=historial, content = formatted_now)
    
###################### CONTROLADOR SERIES    
@app.route('/series')
@login_required
def series():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a la página de Series: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/series.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)    
    
##################### CONTROLADOR PELICULAS  
@app.route('/peliculas')
@login_required
def peliculas():
     # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a la página de Series: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/peliculas.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas ", 
        content = formatted_now)    

#################### CONTROLADOR PARA SALIR DEL SISTEMA   
@app.route('/logout')
def logout():
     # Elimina los datos de la sesión
    session.clear()
    flash('Has cerrado sesión correctamente.')
    
    return redirect(url_for('home'))


# Desactivar caché en rutas protegidas
@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


##### SERIES FRIENDS
#################################################################################

##### SERIES FRIENDS TEMPORADA 1
#################################################################################

@app.route('/friendst1c1')
@login_required
def friendst1c1():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)


@app.route('/friendst1c2')
@login_required
def friendst1c2():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c3')
@login_required
def friendst1c3():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)

@app.route('/friendst1c4')
@login_required
def friendst1c4():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c5')
@login_required
def friendst1c5():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)    
    
@app.route('/friendst1c6')
@login_required
def friendst1c6():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c7')
@login_required
def friendst1c7():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c8')
@login_required
def friendst1c8():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c9')
@login_required
def friendst1c9():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 9: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c9.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c10')
@login_required
def friendst1c10():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 10: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c10.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c11')
@login_required
def friendst1c11():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 11: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c11.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c12')
@login_required
def friendst1c12():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 12: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c12.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c13')
@login_required
def friendst1c13():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 13: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c13.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c14')
@login_required
def friendst1c14():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 14: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c14.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c15')
@login_required
def friendst1c15():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 15: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c15.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c16')
@login_required
def friendst1c16():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 16: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c16.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c17')
@login_required
def friendst1c17():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 17: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c17.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c18')
@login_required
def friendst1c18():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 18: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c18.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c19')
@login_required
def friendst1c19():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 19: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c19.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c20')
@login_required
def friendst1c20():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 20: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c20.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c21')
@login_required
def friendst1c21():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 21: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c21.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c22')
@login_required
def friendst1c22():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 22: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c22.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c23')
@login_required
def friendst1c23():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 23: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c23.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst1c24')
@login_required
def friendst1c24():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T1 Capitulo 24: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst1c24.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES FRIENDS TEMPORADA 7
#################################################################################

@app.route('/friendst7c1')
@login_required
def friendst7c1():
      # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T7 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst7c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst7c2')
@login_required
def friendst7c2():
     # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T7 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst7c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst7c3')
@login_required
def friendst7c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T7 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst7c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES FRIENDS TEMPORADA 8
#################################################################################

@app.route('/friendst8c1')
@login_required
def friendst8c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T8 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst8c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst8c2')
@login_required
def friendst8c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T8 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst8c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst8c3')
@login_required
def friendst8c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T8 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst8c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES FRIENDS TEMPORADA 9
#################################################################################

@app.route('/friendst9c1')
@login_required
def friendst9c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T9 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst9c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst9c2')
@login_required
def friendst9c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T9 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst9c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst9c3')
@login_required
def friendst9c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T9 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst9c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES FRIENDS TEMPORADA 10
#################################################################################

@app.route('/friendst10c1')
@login_required
def friendst10c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T10 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst10c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst10c2')
@login_required
def friendst10c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T10 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst10c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/friendst10c3')
@login_required
def friendst10c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Friends T10 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/friends/friendst10c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES TWO AND A HALF MEN TEMPORADA 1
#################################################################################   

@app.route('/tahmt1c1')
@login_required
def tahmt1c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c2')
@login_required
def tahmt1c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c3')
@login_required
def tahmt1c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c4')
@login_required
def tahmt1c4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c5')
@login_required
def tahmt1c5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c6')
@login_required
def tahmt1c6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c7')
@login_required
def tahmt1c7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c8')
@login_required
def tahmt1c8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c9')
@login_required
def tahmt1c9():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 9: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c9.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c10')
@login_required
def tahmt1c10():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 10: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c10.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c11')
@login_required
def tahmt1c11():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 11: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c11.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c12')
@login_required
def tahmt1c12():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 12: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c12.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c13')
@login_required
def tahmt1c13():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 13: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c13.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c14')
@login_required
def tahmt1c14():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 14: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c14.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c15')
@login_required
def tahmt1c15():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 15: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c15.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c16')
@login_required
def tahmt1c16():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 16: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c16.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c17')
@login_required
def tahmt1c17():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 17: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c17.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c18')
@login_required
def tahmt1c18():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 18: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c18.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c19')
@login_required
def tahmt1c19():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 19: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c19.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c20')
@login_required
def tahmt1c20():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 20: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c20.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c21')
@login_required
def tahmt1c21():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 21: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c21.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c22')
@login_required
def tahmt1c22():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 22: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c22.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c23')
@login_required
def tahmt1c23():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 23: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c23.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/tahmt1c24')
@login_required
def tahmt1c24():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Two and a Half Men T1 Capitulo 24: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/tahm/tahmt1c24.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES SMALLVILLE TEMPORADA 1
#################################################################################   

@app.route('/smallvillet1c1')
@login_required
def smallvillet1c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c2')
@login_required
def smallvillet1c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c3')
@login_required
def smallvillet1c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c4')
@login_required
def smallvillet1c4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c5')
@login_required
def smallvillet1c5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c6')
@login_required
def smallvillet1c6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c7')
@login_required
def smallvillet1c7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c8')
@login_required
def smallvillet1c8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c9')
@login_required
def smallvillet1c9():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 9: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c9.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c10')
@login_required
def smallvillet1c10():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 10: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c10.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c11')
@login_required
def smallvillet1c11():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 11: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c11.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c12')
@login_required
def smallvillet1c12():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 12: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c12.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c13')
@login_required
def smallvillet1c13():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 13: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c13.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c14')
@login_required
def smallvillet1c14():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 14: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c14.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c15')
@login_required
def smallvillet1c15():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 15: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c15.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c16')
@login_required
def smallvillet1c16():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 16: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c16.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c17')
@login_required
def smallvillet1c17():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 17: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c17.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c18')
@login_required
def smallvillet1c18():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 18: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c18.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c19')
@login_required
def smallvillet1c19():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 19: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c19.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c20')
@login_required
def smallvillet1c20():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 20: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c20.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/smallvillet1c21')
@login_required
def smallvillet1c21():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Smallville T1 Capitulo 21: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/smallville/smallvillet1c21.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)


##### SERIES THE MANDALORIAN TEMPORADA 1
#################################################################################   

@app.route('/mandaloriant1c1')
@login_required
def mandaloriant1c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/mandaloriant1c2')
@login_required
def mandaloriant1c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)

@app.route('/mandaloriant1c3')
@login_required
def mandaloriant1c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/mandaloriant1c4')
@login_required
def mandaloriant1c4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/mandaloriant1c5')
@login_required
def mandaloriant1c5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/mandaloriant1c6')
@login_required
def mandaloriant1c6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/mandaloriant1c7')
@login_required
def mandaloriant1c7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)

@app.route('/mandaloriant1c8')
@login_required
def mandaloriant1c8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Mandalorian T1 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/mandalorian/mandaloriant1c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES LOS ANILLOS DE PODER TEMPORADA 1
#################################################################################   

@app.route('/ladpt1c1')
@login_required
def ladpt1c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c2')
@login_required
def ladpt1c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c3')
@login_required
def ladpt1c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c4')
@login_required
def ladpt1c4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c5')
@login_required
def ladpt1c5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c6')
@login_required
def ladpt1c6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T6 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c7')
@login_required
def ladpt1c7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt1c8')
@login_required
def ladpt1c8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T1 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt1c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
##### SERIES LOS ANILLOS DE PODER TEMPORADA 2
#################################################################################    

@app.route('/ladpt2c1')
@login_required
def ladpt2c1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 1: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c1.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c2')
@login_required
def ladpt2c2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c2.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c3')
@login_required
def ladpt2c3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 3: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c3.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c4')
@login_required
def ladpt2c4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c4.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c5')
@login_required
def ladpt2c5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 5: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c5.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c6')
@login_required
def ladpt2c6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c6.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c7')
@login_required
def ladpt2c7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 7: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c7.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    
@app.route('/ladpt2c8')
@login_required
def ladpt2c8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Serie Los Anillos de Poder T2 Capitulo 8: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/ladp/ladpt2c8.html",
        title = "EG90 Series",
        message = "Top Series ", 
        content = formatted_now)
    

##### SECCION DE PELICULAS
#################################################################################

##### SECCION DE COMEDIAS
#################################################################################

@app.route('/whitechicks')
@login_required
def whitechicks():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula White Chicks: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/whitechicks.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

@app.route('/americanpie4')
@login_required
def americanpie4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula American Pie 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/americanpie4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

@app.route('/meangirls')
@login_required
def meangirls():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Chicas Pesadas: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/meangirls.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/seventeenagain')
@login_required
def seventeenagain():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula 17 otra vez: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/seventeenagain.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
@app.route('/reciencasados')
@login_required
def reciencasados():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Recien Casados: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/reciencasados.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/fiftyFirstdates')
@login_required
def fiftyfirstdates():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula 17 otra vez: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/50firstdates.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

##### SECCION DE SUSPENSO
#################################################################################

@app.route('/parpadeadosveces')
@login_required
def parpadeadosveces():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Parpadea dos veces: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/parpadeadosveces.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

    
##### SECCION DE FICCION
#################################################################################

@app.route('/matrix')
@login_required
def matrix():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Matrix: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/matrix.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/matrixrecargado')
@login_required
def matrixrecargado():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Matrix Recargado: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/matrixrecargado.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/terminator2')
@login_required
def terminator2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Terminator 2: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/terminator4')
@login_required
def terminator4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Terminator 4: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
@app.route('/terminator6')
@login_required
def terminator6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula Terminator 6: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (user_id, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator6.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)