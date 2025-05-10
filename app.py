from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_pymongo import PyMongo
from flask_session import Session
from redis import Redis
from bson.objectid import ObjectId
#pip install bcrypt


import bcrypt


app = Flask(__name__)
app.secret_key = 'clave_secreta'

# MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/tienda_db"
mongo = PyMongo(app)

# Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False  # No hacemos sesiones permanentes en este caso
app.config['SESSION_USE_SIGNER'] = True  # Añadir una firma a las sesiones para mayor seguridad
app.config['SESSION_REDIS'] = Redis(host='localhost', port=6379)
Session(app)
redis_conn = Redis(host='localhost', port=6379, decode_responses=True)

# Home
@app.route('/', methods=['GET'])
def index():
    print("Sesión actual:", session)  # 👈 Te dirá si 'usuario' está o no
    productos = list(mongo.db.productos.find())
    usuario = None
    if 'usuario' in session:
        print("Nombre de usuario en sesión:", session['usuario'])
        usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
    return render_template('index.html', productos=productos, usuario=usuario)


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Buscar al usuario en la base de datos MongoDB
        user = mongo.db.usuarios.find_one({
            'username': request.form['username'],
            'password': request.form['password']
        })
        
        if user:
            # Guardar la sesión en Redis
            session['usuario'] = user['username']
            redis_conn.set(f"sesion:{user['username']}", 'activa', ex=3600)  # Expira en 1 hora
            redis_conn.hmset(f"usuario:{user['username']}", {
                'username': user['username'],
                'email': user.get('correo', ''),
                'nombre': user.get('nombre', '')
            })

            # Verificar si el usuario es administrador
            if user.get('admin', False):  # Si el campo 'admin' es True
                flash("Bienvenido, Administrador", "success")
                return redirect(url_for('admin_panel'))  # Redirigir al panel de administrador

            flash("Bienvenido", "success")
            return redirect('/')  # Redirigir al home para usuarios normales

        else:
            flash("Credenciales inválidas", "danger")
    return render_template('login.html')


# Logout
@app.route('/logout')
def logout():
    usuario = session.get('usuario')
    if usuario:
        # Borrar la sesión tanto en Flask como en Redis
        redis_conn.delete(f"sesion:{usuario}")
        redis_conn.delete(f"usuario:{usuario}")
        session.clear()  # Limpiar la sesión del servidor
        flash("Sesión cerrada", "info")
    return redirect('/')

#registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        nombre = request.form['nombre']
        correo = request.form['correo']
        telefono = request.form['telefono']
        password = request.form['password']

        # Verificar si ya existe un usuario con ese nombre de usuario
        if mongo.db.usuarios.find_one({'username': username}):
            flash("El nombre de usuario ya está en uso.", "danger")
            return redirect(url_for('registro'))

        # Hashear la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insertar nuevo usuario
        mongo.db.usuarios.insert_one({
            "username": username,
            "nombre": nombre,
            "correo": correo,
            "telefono": telefono,
            "password": hashed_password,
            "admin": False
        })

        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('registro.html')


# Perfil
@app.route('/perfil')
def perfil():
    if 'usuario' in session:
        usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
        return render_template('perfil.html', usuario=usuario)
    return redirect('/login')


# Panel de administración
@app.route('/admin', methods=['GET'])
def admin_panel():
    if 'usuario' not in session:
        flash("Debes iniciar sesión para acceder al panel de administración", "warning")
        return redirect('/login')
    
    # Obtener los detalles del usuario desde la sesión
    usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
    
    # Verificar si el usuario es un admin
    if not usuario.get('admin', False):
        flash("Acceso denegado. No eres un administrador.", "danger")
        return redirect('/')
    
    # Obtener todos los usuarios que no son administradores
    usuarios_comunes = mongo.db.usuarios.find({'admin': {'$ne': True}})
    productos = list(mongo.db.productos.find())

    return render_template('admin_panel.html', usuario=usuario, productos=productos, usuarios=usuarios_comunes)

# Agregar producto
@app.route('/agregar', methods=['GET', 'POST'])
def agregar():
    if request.method == 'POST':
        mongo.db.productos.insert_one({
            'titulo': request.form['titulo'],
            'descripcion': request.form['descripcion'],
            'imagen': request.form['imagen']
        })
        flash("Producto agregado", "success")
        return redirect('/')
    return render_template('agregar.html')

# VENDER
@app.route('/vender', methods=['GET', 'POST'])
def vender_producto():
    if request.method == 'POST':
        tipo = request.form['tipo']
        precio = float(request.form['precio'])
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        imagen = request.form['imagen']  # Puede ser un URL o nombre de archivo si quieres subir imágenes.

        # Obtener el ID del usuario que está publicando el producto (esto puede ser a través de la sesión).
        usuario_id = session.get('usuario_id')  # Cambiar según cómo gestionas la autenticación.

        # Guardar el producto en la base de datos
        mongo.db.productos.insert_one({
            "tipo": tipo,
            "precio": precio,
            "titulo": titulo,
            "descripcion": descripcion,
            "imagen": imagen,
            "usuario_id": usuario_id  # Asociamos el producto con el usuario que lo publica
        })
        return redirect('/mis_productos')

    return render_template('vender.html')

#MIS Productos
@app.route('/mis_productos')
def mis_productos():
    usuario_id = session.get('usuario_id')  # Obtener el ID del usuario logueado
    productos = mongo.db.productos.find({"usuario_id": usuario_id})
    return render_template('mis_productos.html', productos=productos)


# Ver producto (requiere sesión y sube ranking)
@app.route('/producto/<id>')
def ver_producto(id):
    if 'usuario' not in session:
        flash("Inicia sesión para ver productos", "warning")
        return redirect('/login')
    producto = mongo.db.productos.find_one({'_id': ObjectId(id)})
    if producto:
        redis_conn.zincrby("mas_vendidos", 1, producto['titulo'])
    return render_template("producto.html", producto=producto)

#EDITAR PRODUCTO
@app.route('/editar_producto/<id>', methods=['GET', 'POST'])
def editar_producto(id):
    # Buscar el producto por su ID
    producto = mongo.db.productos.find_one({"_id": ObjectId(id)})
    
    # Si el método es POST, significa que se envió el formulario
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        imagen = request.form['imagen']  # Esto puede ser la URL de la imagen o el nombre del archivo
        
        # Actualizar la información del producto en la base de datos
        mongo.db.productos.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"titulo": titulo, "descripcion": descripcion, "imagen": imagen}}
        )
        # Redirigir a la página de administración o donde se necesite
        return redirect('/admin')  # Cambia esto según tu ruta de panel de administración
    
    # Si el método es GET, simplemente mostrar el formulario con los datos actuales del producto
    return render_template('editar_producto.html', producto=producto)

#ELIMINAR PRODUCTO
@app.route('/eliminar_producto/<id>', methods=['GET'])
def eliminar_producto(id):
    # Eliminar el producto de la base de datos usando el ID
    mongo.db.productos.delete_one({"_id": ObjectId(id)})
    # Redirigir a la página de administración después de eliminar
    return redirect('/admin')  # Cambia esto según tu ruta de panel de administración

#EDITAR USUARIO
@app.route('/editar_usuario/<id>', methods=['GET', 'POST'])
def editar_usuario(id):
    # Buscar el usuario por su ID
    usuario = mongo.db.usuarios.find_one({"_id": ObjectId(id)})
    
    # Si el método es POST, significa que se envió el formulario
    if request.method == 'POST':
        username = request.form['username']
        correo = request.form['correo']
        nombre = request.form['nombre']
        telefono = request.form['telefono']
        
        # Actualizar la información del usuario en la base de datos
        mongo.db.usuarios.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"username": username, "correo": correo, "nombre": nombre, "telefono": telefono}}
        )
        # Redirigir a la página de administración o donde se necesite
        return redirect('/admin')  # Cambia esto según tu ruta de panel de administración
    
    # Si el método es GET, simplemente mostrar el formulario con los datos actuales del usuario
    return render_template('editar_usuario.html', usuario=usuario)

#ELIMINAR USUARIO
@app.route('/eliminar_usuario/<id>', methods=['GET'])
def eliminar_usuario(id):
    mongo.db.usuarios.delete_one({"_id": ObjectId(id)})
    return redirect('/admin')

# Configuración de la subida de archivos
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if __name__ == '__main__':
    app.run(debug=True)

