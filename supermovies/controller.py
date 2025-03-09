# Librerias y Dependencias
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from functools import wraps
import plotly.graph_objs as go
from plotly.offline import plot
from datetime import datetime, timedelta
from supermovies import app
import os

password = "ElGuada90.#"
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')

# Middleware para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar si el usuario tiene un rol específico
def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Debes iniciar sesión para acceder a esta página.', 'error')
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            
            if user_role not in required_roles: # Verifica si el rol del usuario NO ESTÁ en los roles requeridos
                nombre = session.get('nombre')
                apellido = session.get('apellido')
                nombre_completo = f"{nombre} {apellido}" if nombre and apellido else "Usuario"   # Obtener nombre completo
                flash(('No tienes permiso para acceder a esta página.', nombre_completo), 'error')
                return redirect(url_for('peliculas_contenido'))  # Redirigir a una página sin restricciones
            return f(*args, **kwargs)
        return decorated_function
    return decorator

##################### CONTROLADOR DE INDEX

@app.route('/home')
def home():
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "login.html",
        title = "EG90  LOGIN",
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
                    session['nombre'] = user['Nombre']
                    session['apellido'] = user['Apellido']
                    session.permanent = True  # Activar sesión persistente
                    app.permanent_session_lifetime = timedelta(days=7)  # Duración de la sesión
                    
                     # Registrar la acción de login
                    user_id = session.get('user_id')
                    user_name = session.get('username')
                    accion = f"Inicio de sesión exitoso: {user_name}"
                    
                    nombre_completo = f"{user['Nombre']} {user['Apellido']}"  # Obtener nombre completo
                    flash(("Inicio de sesión exitoso, Bienvenido!", nombre_completo), "success") 
                    return redirect(url_for('peliculas_contenido'))
                    
                    
                else:
                    flash('Tu cuenta está bloqueada. Contacta al administrador.', 'error')
            else:
                flash('Contraseña incorrecta', 'error')
        else:
            flash('Ingrese su Usuario y Contraseña', 'error')
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "login.html", 
        title="EG90 LOGIN", 
        message="Top Series", 
        content=formatted_now)

#############################################################################################    

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
        flash('Usuario registrado exitosamente', 'success')
        return redirect(url_for('login'))
    return render_template(
        "registro.html",
        title="EG90 FORM", 
        message="Top Series", 
        )


# ADMINISTRATIVO
#########################################################################################

# Ruta para ver y gestionar usuarios
@app.route('/usuarios')
@login_required
@role_required('Admin', 'SuperUser')
def usuarios():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "usuarios.html", 
        usuarios=usuarios, 
        content = formatted_now)
    

# MODULO PARA EDITAR USUARIOS
#########################################################################################

@app.route('/editar_usuario', methods=['POST'])
@login_required
@role_required('Admin', 'SuperUser')
def editar_usuario():
    id_usuario = request.form['id_usuario']
    usuario = request.form['usuario']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    email = request.form['email']
    rol = request.form['rol']
    estado = request.form['estado']
    nueva_contrasena = request.form['contraseña']

    cursor = mysql.connection.cursor()

    # Obtener el usuario actual de la base de datos
    cursor.execute('SELECT * FROM Usuarios WHERE ID_Usuario = %s', (id_usuario,))
    usuario_actual = cursor.fetchone()

    # Crear una lista para almacenar los campos que se van a actualizar
    campos_actualizados = []
    valores_actualizados = []

    # Comparar los valores del formulario con los valores actuales
    if usuario != usuario_actual[2]:  # Usuario es el índice 2
        campos_actualizados.append('Usuario = %s')
        valores_actualizados.append(usuario)

    if nombre != usuario_actual[4]:  # Nombre es el índice 4
        campos_actualizados.append('Nombre = %s')
        valores_actualizados.append(nombre)

    if apellido != usuario_actual[5]:  # Apellido es el índice 5
        campos_actualizados.append('Apellido = %s')
        valores_actualizados.append(apellido)

    if email != usuario_actual[6]:  # Email es el índice 6
        campos_actualizados.append('Email = %s')
        valores_actualizados.append(email)

    if rol != usuario_actual[7]:  # Rol es el índice 7
        campos_actualizados.append('Rol = %s')
        valores_actualizados.append(rol)

    if estado != usuario_actual[8]:  # Estado es el índice 8
        campos_actualizados.append('Estado = %s')
        valores_actualizados.append(estado)

    if nueva_contrasena:
        hashed_password = generate_password_hash(nueva_contrasena, method='pbkdf2:sha256')
        campos_actualizados.append('Contraseña = %s')
        valores_actualizados.append(hashed_password)

    # Construir la consulta UPDATE dinámicamente
    if campos_actualizados:
        consulta_update = 'UPDATE Usuarios SET ' + ', '.join(campos_actualizados) + ' WHERE ID_Usuario = %s'
        valores_actualizados.append(id_usuario)
        cursor.execute(consulta_update, tuple(valores_actualizados))
        mysql.connection.commit()
        flash('Usuario actualizado correctamente', 'success')
    else:
        flash('No se realizaron cambios en el usuario', 'info')

    cursor.close()
    return redirect(url_for('usuarios'))


# Ruta para bloquear/desbloquear usuario
#########################################################################################
@app.route('/bloquear/<int:id>')
@login_required
@role_required('Admin', 'SuperUser')
def bloquear(id):
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET Estado = CASE WHEN Estado = 0 THEN 1 ELSE 0 END WHERE Id_Usuario = %s", (id,))
    conn.commit()
    flash('Estado de bloqueo cambiado', 'warning')

    # Obtener el usuario actual (administrador) desde la sesión
    admin_id = session.get('user_id')
    admin_name = session.get('username')

    # Obtener el nombre del usuario cuya cuenta fue modificada y su estado actual
    cursor.execute("SELECT Usuario, Estado FROM usuarios WHERE Id_Usuario = %s", (id,))
    usuario_modificado = cursor.fetchone()
    if usuario_modificado:
        usuario_modificado_name = usuario_modificado[0]
        usuario_modificado_estado = usuario_modificado[1]  # Obtener el estado actual
    else:
        usuario_modificado_name = "Usuario desconocido"
        usuario_modificado_estado = None

    # Registrar la acción en el historial
    if usuario_modificado_estado is not None:
        accion = f"El administrador {admin_name} { 'bloqueó' if usuario_modificado_estado == 1 else 'desbloqueó' } la cuenta del usuario: {usuario_modificado_name}"
    else:
        accion = f"El administrador {admin_name} intentó cambiar el estado de un usuario desconocido"

    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, Accion) VALUES (%s, %s)",
        (admin_id, accion)
    )
    mysql.connection.commit()
    return redirect(url_for('usuarios'))



# Ruta para ver historial
#########################################################################################
@app.route('/historial')
@login_required
@role_required('Admin', 'SuperUser')
def historial():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM historial ORDER BY Fecha DESC")
    historial = cursor.fetchall()
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "historial.html", 
        historial=historial, 
        content = formatted_now)
    
    
# DASHBOARD TABLAS Y GRAFICOS PLOTLY
#########################################################################################

def obtener_cantidad_contenido_por_tipo():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("""
        select coalesce(tipo, 'Total General') AS Categorias, count(Id_contenido) AS Cantidad 
        from contenido 
        group by tipo with rollup;
    """)
    resultados = cursor.fetchall()
    return resultados

def obtener_cantidad_contenido_por_genero():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("""
        select coalesce(Genero, 'Total General') AS Genero, count(Id_contenido) AS Cantidad 
        from contenido 
        where tipo = 'Peliculas' 
        group by Genero with rollup;
    """)
    resultados = cursor.fetchall()
    return resultados

def obtener_cantidad_contenido_visto_por_usuario():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("""
        select coalesce(Id_Usuario, 'Total General') AS Id_Usuario , count(Id_Contenido) from historial
        group by Id_Usuario with rollup;
    """)
    resultados = cursor.fetchall()
    return resultados

@app.route('/contenido')
@login_required
@role_required('Admin', 'SuperUser')
def contenido():
    datos_tipo = obtener_cantidad_contenido_por_tipo()
    datos_genero = obtener_cantidad_contenido_por_genero()
    datos_usuario = obtener_cantidad_contenido_visto_por_usuario()
    return render_template(
        'contenido.html', 
        title="Contenido",
        datos_tipo=datos_tipo, 
        datos_genero=datos_genero, 
        datos_usuario=datos_usuario)


# DASHBOARD GRAFICOS
#########################################################################################
def generar_grafico_plotly_tipos(datos):
    categorias = [dato[0] for dato in datos]
    cantidades = [dato[1] for dato in datos]

    fig = go.Figure(data=[go.Bar(x=categorias, y=cantidades)])
    fig.update_layout(title='Cantidad de Contenido por Tipo', xaxis_title='Categorías', yaxis_title='Cantidad')
    grafico_plotly = plot(fig, output_type='div')
    return grafico_plotly

def generar_grafico_plotly_generos(datos):
    generos = [dato[0] for dato in datos]
    cantidades = [dato[1] for dato in datos]

    fig = go.Figure(data=[go.Bar(x=generos, y=cantidades)])
    fig.update_layout(title='Cantidad de Películas por Género', xaxis_title='Géneros', yaxis_title='Cantidad')
    grafico_plotly = plot(fig, output_type='div')
    return grafico_plotly

def generar_grafico_plotly_usuarios(datos):
    usuarios = [str(dato[0]) for dato in datos]
    cantidades = [dato[1] for dato in datos]

    fig = go.Figure(data=[go.Scatter(x=usuarios, y=cantidades, mode="lines")])
    fig.update_layout(title='Contenido Visto por Usuario', xaxis_title='Usuarios', yaxis_title='Cantidad')
    grafico_plotly = plot(fig, output_type='div')
    return grafico_plotly

@app.route('/dashboard')
@login_required
@role_required('Admin', 'SuperUser')
def dashboard():
    datos_tipo = obtener_cantidad_contenido_por_tipo()
    datos_genero = obtener_cantidad_contenido_por_genero()
    datos_usuario = obtener_cantidad_contenido_visto_por_usuario()

    grafico_plotly_tipos = generar_grafico_plotly_tipos(datos_tipo)
    grafico_plotly_generos = generar_grafico_plotly_generos(datos_genero)
    grafico_plotly_usuarios = generar_grafico_plotly_usuarios(datos_usuario)

    return render_template(
        'dashboard.html', 
        title="Dashboard",
        grafico_plotly_tipos=grafico_plotly_tipos,
        grafico_plotly_generos=grafico_plotly_generos,
        grafico_plotly_usuarios=grafico_plotly_usuarios
    )
    
    

###################### CONTROLADOR CONTENIDO DE ANIMES    
@app.route('/animes_contenido')
@login_required
def animes_contenido():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    conn = mysql.connection
    cursor = conn.cursor()
    # Consulta solo los registros donde tipo sea 'Peliculas'
    cursor.execute("""
                    SELECT c.Titulo, c.Genero, c.Imagen, c.Enlace, Episodio AS id_episodio, e.Temporada  
                    FROM contenido c
                    LEFT JOIN episodios e ON e.ID_Contenido = c.ID_Contenido
                    WHERE c.tipo = %s
                    AND e.Temporada = 1
                    AND e.Episodio = 1  
                    ORDER BY c.Titulo
                     """, ('Animes',))
     
    results = cursor.fetchall()
    
    results = [
        {"Titulo": row[0], "Genero": row[1], "Imagen": row[2], "Enlace": row[3], "episodio": row[4], "temporada": row[5]}
        for row in results
    ]
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "animes/animes.html",
        title = "EG90 Animes",
        message = "Bienvenido " + user_name,
        content = formatted_now,
        results=results)    

    
###################### CONTROLADOR CONTENIDO DE SERIES    
@app.route('/series_contenido')
@login_required
def series_contenido():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    conn = mysql.connection
    cursor = conn.cursor()
    # Consulta solo los registros donde tipo sea 'Series'
    cursor.execute("""
                    SELECT c.Titulo, c.Genero, c.Imagen, c.Enlace, Episodio AS id_episodio, e.Temporada  
                    FROM contenido c
                    LEFT JOIN episodios e ON e.ID_Contenido = c.ID_Contenido
                    WHERE c.tipo = %s
                    AND e.Temporada = 1
                    AND e.Episodio = 1  
                    ORDER BY c.Titulo
                     """, ('Series',))
    
    results = cursor.fetchall()
    
    results = [
        {"Titulo": row[0], "Genero": row[1], "Imagen": row[2], "Enlace": row[3], "episodio": row[4], "temporada": row[5]}
        for row in results
    ]
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "series/series.html",
        title = "EG90 Series",
        message = "Bienvenido " + user_name,
        content = formatted_now,
        results=results)    
    
##################### CONTROLADOR DE CONTENIDO DE PELICULAS  
@app.route('/')
@app.route('/peliculas_contenido')
@login_required
def peliculas_contenido():
     # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    conn = mysql.connection
    cursor = conn.cursor()
   # Consulta solo los registros donde tipo sea 'Peliculas'
    cursor.execute("SELECT Titulo, Genero, Imagen, Enlace FROM contenido WHERE tipo = %s", ('Peliculas',))
    results = cursor.fetchall()
    
    results = [
        {"Titulo": row[0], "Genero": row[1], "Imagen": row[2], "Enlace": row[3]}
        for row in results
    ]
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/peliculas.html",
        title = "EG90 Peliculas",
        message = "Bienvenido " + user_name,
        content = formatted_now,
        results=results)    


########################### CONTROLADOR MOTOR DE BUSQUEDA

@app.route('/buscar', methods=['GET'])
def buscar():
    query = request.args.get('q')  # Obtiene el término de búsqueda
    if query:
        # Si la consulta contiene "Estrenos", redirige a la Estrenos.html
        
        if 'estrenos' in query.lower():
            return redirect(url_for('estrenos', q=query))

        # Si no, busca en la base de datos para películas
        cursor = mysql.connection.cursor()
        cursor.execute("""
                       
            SELECT c.ID_Contenido, c.Titulo, c.Genero, c.Imagen, c.Enlace,
                (SELECT MIN(e.Episodio) 
                FROM episodios e 
                WHERE e.ID_Contenido = c.ID_Contenido) AS id_episodio
            FROM contenido c 
            WHERE c.Titulo LIKE %s OR c.Genero LIKE %s OR c.Tipo LIKE %s OR c.Categoria LIKE %s
            ORDER BY c.Titulo
        """, (f"%{query}%", f"%{query}%", f"%{query}%" , f"%{query}%" ))
        results = cursor.fetchall()  # Obtiene los resultados
        cursor.close()

        # Transformar los resultados a un formato de lista de diccionarios
        results = [
            {"ID_Contenido": row[0],
             "Titulo": row[1], 
             "Genero": row[2], 
             "Imagen": row[3], 
             "Enlace": row[4], 
             "episodio": row[5]}
            for row in results
        ]

        # Renderiza la plantilla con los resultados
        return render_template(
            'peliculas/contenido_busqueda.html',
            query=query,
            results=results
        )

    # Si no hay consulta, redirige al inicio
    return redirect(url_for('peliculas_contenido'))


#################### CONTROLADOR PARA SALIR DEL SISTEMA   
@app.route('/logout')
def logout():
     # Elimina los datos de la sesión
    session.clear()
    flash('Has cerrado sesión correctamente.' , 'info')
    
    return redirect(url_for('login'))


# Desactivar caché en rutas protegidas
@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



##### SECCION DE ANIMES
################################################################################

##### ANIMES MAZINKAISER TEMPORADA 1
################################################################################

@app.route('/mazinkaiser/<int:temporada>/<int:id_episodio>')
@login_required
def mazinkaiser_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 71 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 71 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/mazinkaiser/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 71 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/mazinkaiser/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 71
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Anime Mazinkaiser T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 71, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "animes/mazinkaiser/mazinkaiser.html",
        serie='mazinkaiser',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    
    
    
##### ANIMES GRENDIZER U TEMPORADA 1
################################################################################

@app.route('/grendizeru/<int:temporada>/<int:id_episodio>')
@login_required
def grendizeru_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 72 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 72 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/grendizeru/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 72 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/grendizeru/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 72
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Anime Grendizer U T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 72, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "animes/grendizeru/grendizeru.html",
        serie='grendizeru',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    
    
    
##### ANIMES KOUTETSUSHIN JEEG TEMPORADA 1
################################################################################

@app.route('/koutetsushinjeeg/<int:temporada>/<int:id_episodio>')
@login_required
def koutetsushinjeeg_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 73 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 73 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/koutetsushinjeeg/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 73 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/koutetsushinjeeg/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 73
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Anime Koutetsushin Jeeg T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 73, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "animes/koutetsushinjeeg/koutetsushinjeeg.html",
        serie='koutetsushinjeeg',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    
    
    
##### ANIMES KAIJU 8 TEMPORADA 1
################################################################################

@app.route('/kaiju8/<int:temporada>/<int:id_episodio>')
@login_required
def kaiju8_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 74 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 74 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/kaiju8/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 74 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/kaiju8/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 74
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Anime Kaiju 8 T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 74, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "animes/kaiju8/kaiju8.html",
        serie='kaiju8',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    
    

##### ANIMES MASTERS OF THE UNIVERSE TEMPORADAS
################################################################################

@app.route('/mastersoftheuniverse/<int:temporada>/<int:id_episodio>')
@login_required
def mastersoftheuniverse_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 75 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 75 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/mastersoftheuniverse/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 75 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/mastersoftheuniverse/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 75
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Anime Masters of the Universe T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 75, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "animes/mastersoftheuniverse/mastersoftheuniverse.html",
        serie='mastersoftheuniverse',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
      
    
##### SECCION DE SERIES
#################################################################################

##### SERIES FRIENDS TEMPORADAS
#################################################################################

@app.route('/friends/<int:temporada>/<int:id_episodio>')
@login_required
def friends_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 50 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 50 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/friends/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 50 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/friends/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 50
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Friends T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 50, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/friends/friends.html",
        serie='friends',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )

     

##### SERIES TWO AND A HALF MEN TEMPORADAS
#################################################################################

@app.route('/tahm/<int:temporada>/<int:id_episodio>')
@login_required
def tahm_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 51 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 51 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/tahm/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 51 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/tahm/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 51
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Two and a half Men T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 51, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/tahm/tahm.html",
        serie='tahm',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    

##### SERIES SMALLVILLE TEMPORADAS
#################################################################################

@app.route('/smallville/<int:temporada>/<int:id_episodio>')
@login_required
def smallville_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 52 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 52 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/smallville/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 52 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/smallville/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 52
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Smallville T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 52, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/smallville/smallville.html",
        serie='smallville',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
    
        
##### SERIES EL SEÑOR DE LOS ANILLOS - LOS ANILLOS DE PODER TEMPORADAS
#################################################################################

@app.route('/ladp/<int:temporada>/<int:id_episodio>')
@login_required
def ladp_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 54 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 54 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/ladp/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 54 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/ladp/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 54
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Los Anillos de Poder T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 54, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/ladp/ladp.html",
        serie='ladp',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url,
    )
       
    
##### JUEGO DE TRONOS - LA CASA DEL DRAGON TEMPORADAS
#################################################################################

@app.route('/dragonhouse/<int:temporada>/<int:id_episodio>')
@login_required
def dragonhouse_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 55 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 55 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/dragonhouse/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 55 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/dragonhouse/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 55
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie La Casa del Dragon T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 55, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/dragonhouse/dragonhouse.html",
        serie='dragonhouse',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url 
    )   
    
    
    
##### JUEGO DE TRONOS
#################################################################################

@app.route('/juegodetronos/<int:temporada>/<int:id_episodio>')
@login_required
def juegodetronos_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 69 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 69 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/juegodetronos/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 69 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/juegodetronos/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 69
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Juego de Tronos T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 69, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/gameofthrones/juegodetronos.html",
        serie='juegodetronos',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url 
    )
    
    

##### SERIES STAR WARS OBI WAN KENOBI TEMPORADA 1
#################################################################################

@app.route('/obiwankenobi/<int:temporada>/<int:id_episodio>')
@login_required
def obiwankenobi_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 65 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 65 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/obiwankenobi/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 65 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/obiwankenobi/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 65
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Obi Wan Kenobi T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 66, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/obiwankenobi/obiwankenobi.html",
        serie='obiwankenobi',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url 
    ) 
    
     
##### SERIES SKELETON CREW TEMPORADA 1
#################################################################################

@app.route('/skeletoncrew/<int:temporada>/<int:id_episodio>')
@login_required
def skeletoncrew_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 66 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 66 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/skeletoncrew/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 66 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/skeletoncrew/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 66
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie Skeleton Crew T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 66, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/skeletoncrew/skeletoncrew.html",
        serie='skeletoncrew',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url 
    )
    
    

##### SERIES THE MANDALORIAN TEMPORADA 1
#################################################################################   

@app.route('/mandalorian/<int:temporada>/<int:id_episodio>')
@login_required
def mandalorian_episodios(temporada, id_episodio):
    # Conexión a la base de datos
    cursor = mysql.connection.cursor()

    # Obtener información del episodio actual
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 53 AND Temporada = %s AND Episodio = %s
    """, (temporada, id_episodio,))
    episodio_actual = cursor.fetchone()

    if not episodio_actual:
        cursor.close()
        return "Episodio no encontrado", 404

    temporada_actual, episodio_num, titulo, enlace_video = episodio_actual

    # Obtener el episodio anterior
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 53 AND Temporada = %s AND Episodio < %s
        ORDER BY Episodio DESC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_prev = cursor.fetchone()
    prev_url = f"/mandalorian/{temporada}/{episodio_prev[0]}" if episodio_prev else None

    # Obtener el episodio siguiente
    cursor.execute("""
        SELECT Episodio FROM episodios
        WHERE ID_Contenido = 53 AND Temporada = %s AND Episodio > %s
        ORDER BY Episodio ASC LIMIT 1
    """, (temporada_actual, episodio_num))
    episodio_next = cursor.fetchone()
    next_url = f"/mandalorian/{temporada}/{episodio_next[0]}" if episodio_next else None

    # Obtener todos los episodios agrupados por temporada
    cursor.execute("""
        SELECT Temporada, Episodio, Titulo, Enlace_Video
        FROM episodios
        WHERE ID_Contenido = 53
        ORDER BY Temporada, Episodio
    """)
    episodios = cursor.fetchall()
    cursor.close()

    # Transformar resultados en diccionario por temporadas
    temporadas = {}
    for temporada, episodio, titulo, enlace in episodios:
        if temporada not in temporadas:
            temporadas[temporada] = []
        temporadas[temporada].append({
            "Episodio": episodio,
            "Titulo": titulo,
            "Enlace_Video": enlace
        })

    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Registrar acción en historial
    accion = f"Serie The Madalorian T{temporada_actual} Capítulo {episodio_num}: {user_name}"
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, 53, accion)
    )
    mysql.connection.commit()

    # Obtener la fecha actual
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")

    return render_template(
        "series/mandalorian/mandalorian.html",
        serie='mandalorian',
        title="EG90 Series",
        message=f"Episodio {episodio_num} - Temporada {temporada_actual}",
        content=formatted_now,
        temporadas=temporadas,
        video_url=enlace_video,
        prev_url=prev_url,
        next_url=next_url 
    )
    
    


##### SECCION DE PELICULAS
#################################################################################

##### SECCION DE ACCION
#################################################################################

@app.route('/fury')
@login_required
def fury():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('fury',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/fury.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/rambo1')
@login_required
def rambo1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rambo1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rambo1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/rambo2')
@login_required
def rambo2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rambo2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rambo2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/rambo3')
@login_required
def rambo3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rambo3',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rambo3.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/rambo4')
@login_required
def rambo4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rambo4',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rambo4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/rambo5')
@login_required
def rambo5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rambo5',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rambo5.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/rapidoyfurioso1')
@login_required
def rapidoyfurioso1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/rapidoyfurioso2')
@login_required
def rapidoyfurioso2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/rapidoyfurioso3')
@login_required
def rapidoyfurioso3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso3',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso3.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/rapidoyfurioso4')
@login_required
def rapidoyfurioso4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso4',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/rapidoyfurioso5')
@login_required
def rapidoyfurioso5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso5',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso5.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/rapidoyfurioso6')
@login_required
def rapidoyfurioso6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso6',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso6.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/rapidoyfurioso7')
@login_required
def rapidoyfurioso7():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso7',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso7.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/rapidoyfurios8')
@login_required
def rapidoyfurioso8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('rapidoyfurioso8',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/rapidoyfurioso8.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/enemigopublico')
@login_required
def enemigopublico():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('enemigopublico',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/enemigopublico.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/infiltrados')
@login_required
def infiltrados():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('infiltrados',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/accion/infiltrados.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
    
##### SECCION DE ANIMADAS
#################################################################################

@app.route('/lluviadehamburguesas2')
@login_required
def lluviadehamburguesas2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lluviadehamburguesas2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/animadas/lluviadehamburguesas2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
##### SECCION DE AVENTURAS
#################################################################################

@app.route('/lordrings1')
@login_required
def lordrings1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lordrings1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/aventura/lordrings1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/lamomia')
@login_required
def lamomia():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lamomia',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/aventura/lamomia.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/lamomia2')
@login_required
def lamomia2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lamomia2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/aventura/lamomia2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)    
    
    
@app.route('/animalesfantasticos2')
@login_required
def animalesfantasticos2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('animalesfantasticos2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/aventura/animalesfantasticos2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

    
@app.route('/narnia1')
@login_required
def narnia1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('narnia1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/aventura/narnia1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    


##### SECCION DE COMEDIAS
#################################################################################

@app.route('/bridget4')
@login_required
def bridget4():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('bridget4',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/bridgetjones4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/siyotuviera30')
@login_required
def siyotuviera30():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('siyotuviera30',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/siyotuviera30.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/todascontrajohn')
@login_required
def todascontrajohn():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('todascontrajohn',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/todascontrajohn.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/thehotchick')
@login_required
def thehotchick():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('thehotchick',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/thehotchick.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/whitechicks')
@login_required
def whitechicks():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('whitechicks',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('americanpie4',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('meangirls',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('seventeenagain',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
         "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('reciencasados',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/reciencasados.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/fiftyfirstdates')
@login_required
def fiftyfirstdates():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('fiftyfirstdates',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/50firstdates.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/zohan')
@login_required
def zohan():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('zohan',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/comedias/zohan.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
    
##### SECCION DE DC UNIVERSE
#################################################################################

@app.route('/Justiceleague')
@login_required
def Justiceleague():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('Justiceleague',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/dcuniverse/justiceleague.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/batmanbegins')
@login_required
def batmanbegins():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('batmanbegins',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/dcuniverse/batmanbegins.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    


##### SECCION DE DRAMA
#################################################################################

@app.route('/pearlharbor')
@login_required
def pearlharbor():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('pearlharbor',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/pearlharbor.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/gladiador')
@login_required
def gladiador():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('gladiador',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/gladiador.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)    
    
    
@app.route('/courageous')
@login_required
def courageous():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('courageous',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/courageous.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/lacabana')
@login_required
def lacabana():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lacabana',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/lacabana.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/braveheart')
@login_required
def braveheart():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('braveheart',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/braveheart.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/eldiablovistealamoda')
@login_required
def eldiablovistealamoda():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('eldiablovistealamoda',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/eldiablovistealamoda.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/elpadrino1')
@login_required
def elpadrino1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('elpadrino1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/elpadrino1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/apruebadefuego')
@login_required
def apruebadefuego():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('apruebadefuego',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/apruebadefuego.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

@app.route('/enbuscadefelicidad')
@login_required
def enbuscadefelicidad():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('enbuscadefelicidad',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/enbuscadefelicidad.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

@app.route('/mile8')
@login_required
def mile8():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('mile8',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/drama/8mile.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)

    
##### SECCION DE FICCION
#################################################################################

@app.route('/starwars1')
@login_required
def starwars1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('starwars1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/starwars1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/starwars2')
@login_required
def starwars2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('starwars2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/starwars2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/pacificrim')
@login_required
def pacificrim():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('pacificrim',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/pacificrim.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)



@app.route('/yorobot')
@login_required
def yorobot():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('yorobot',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/yorobot.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)   
    

@app.route('/matrix')
@login_required
def matrix():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('matrix',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('matrixrecargado',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/matrixrecargado.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
@app.route('/matrixrevoluciones')
@login_required
def matrixrevoluciones():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('matrixrevoluciones',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/matrixrevoluciones.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/matrixresurreciones')
@login_required
def matrixresurrecciones():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('matrixresurrecciones',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/matrixresurrecciones.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/terminator2')
@login_required
def terminator2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('terminator2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
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
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('terminator4',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator4.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/terminator5')
@login_required
def terminator5():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('terminator5',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator5.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)    

    
@app.route('/terminator6')
@login_required
def terminator6():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('terminator6',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/terminator6.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/dejavu')
@login_required
def dejavu():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('dejavu',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/dejavu.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/volveralfuturo1')
@login_required
def volveralfuturo1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('volveralfuturo1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/volveralfuturo1.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    

@app.route('/volveralfuturo2')
@login_required
def volveralfuturo2():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('volveralfuturo2',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/volveralfuturo2.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
@app.route('/volveralfuturo3')
@login_required
def volveralfuturo3():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('volveralfuturo3',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/volveralfuturo3.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/bumblebee')    
@login_required
def bumblebee():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('bumblebee',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/transformersbumblebee.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
    
@app.route('/endergames')    
@login_required
def endergames():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('endergames',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/endergames.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/speedracer')    
@login_required
def speedracer():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('speedracer',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/speedracer.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/avatar1')    
@login_required
def avatar1():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('avatar1',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/ficcion/avatar.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
        
    
    
##### SECCION DE MARVEL STUDIOS
#################################################################################

@app.route('/xmenpg')
@login_required
def xmenpg():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('xmenpg',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/marvel/xmenpg.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/capcw')
@login_required
def capcw():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('capcw',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/marvel/capcw.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
    
##### SECCION DE SUSPENSO
#################################################################################

@app.route('/lucy')
@login_required
def lucy():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('lucy',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/lucy.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/draculauntold')
@login_required
def draculauntold():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('draculauntold',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/draculauntold.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)


@app.route('/parpadeadosveces')
@login_required
def parpadeadosveces():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('parpadeadosveces',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/parpadeadosveces.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/elsilencio')
@login_required
def elsilencio():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('elsilencio',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/elsilenciodeloscorderos.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)
    
    
@app.route('/dragonrojo')
@login_required
def dragonrojo():
    # Obtener el usuario actual desde la sesión
    user_id = session.get('user_id')
    user_name = session.get('username')
    
    # Obtener Id_Contendido
    cursor = mysql.connection.cursor()
    # consulta a la db
    cursor.execute(
        "SELECT Id_contenido, Titulo FROM Contenido WHERE enlace = %s", ('dragonrojo',) )
    
    resultado = cursor.fetchone()  # Obtener un solo resultado
    if resultado is None:
        return "Contenido no encontrado", 404

    id_contenido, titulo = resultado  # Extraer los valores correctamente
    
    # Registrar la acción en el historial
    accion = f"Accedió a Pelicula {titulo}: {user_name}"
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "INSERT INTO Historial (ID_Usuario, ID_Contenido, Accion) VALUES (%s, %s, %s)",
        (user_id, id_contenido, accion)
    )
    mysql.connection.commit()  # Confirmar la inserción en la base de datos
    
    now = datetime.now()
    formatted_now = now.strftime("%A, %d %B, %Y at %I:%M:%S %p")
    return render_template(
        "peliculas/suspenso/dragonrojo.html",
        title = "EG90 Peliculas",
        message = "Top Peliculas", 
        content = formatted_now)