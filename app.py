from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_pymongo import PyMongo
from flask_session import Session
from redis import Redis
from bson.objectid import ObjectId

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
        # Obtener los datos del formulario
        username = request.form['username']
        correo = request.form['correo']
        password = request.form['password']
        
        # Encriptar la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insertar el usuario en la base de datos
        mongo.db.usuarios.insert_one({
            "username": username,
            "correo": correo,
            "password": hashed_password,
            "admin": False  # Por defecto, los nuevos usuarios son comunes
        })
        return redirect(url_for('login'))  # Cambia a la ruta que desees
        
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
