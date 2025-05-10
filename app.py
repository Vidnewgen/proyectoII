from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_pymongo import PyMongo
from flask_session import Session
from redis import Redis
from bson.objectid import ObjectId
import bcrypt

app = Flask(__name__)
app.secret_key = 'clave_secreta'

# Configuración de MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/tienda_db"
mongo = PyMongo(app)

# Configuración de Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = Redis(host='localhost', port=6379)
Session(app)

# Conexión a Redis
redis_conn = Redis(host='localhost', port=6379, decode_responses=True)

# Ruta principal
@app.route('/', methods=['GET'])
def index():
    print("Sesión actual:", session)
    productos = list(mongo.db.productos.find())
    usuario = mongo.db.usuarios.find_one({'username': session.get('usuario')}) if 'usuario' in session else None
    return render_template('index.html', productos=productos, usuario=usuario)

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = mongo.db.usuarios.find_one({
            'username': request.form['username']
        })
        
        if user and bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password']):
            session['usuario'] = user['username']
            redis_conn.set(f"sesion:{user['username']}", 'activa', ex=3600)
            redis_conn.hmset(f"usuario:{user['username']}", {
                'username': user['username'],
                'email': user.get('correo', ''),
                'nombre': user.get('nombre', '')
            })

            flash("Bienvenido, Administrador" if user.get('admin', False) else "Bienvenido", "success")
            return redirect(url_for('admin_panel' if user.get('admin', False) else '/'))

        flash("Credenciales inválidas", "danger")
    return render_template('login.html')

# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    usuario = session.get('usuario')
    if usuario:
        redis_conn.delete(f"sesion:{usuario}")
        redis_conn.delete(f"usuario:{usuario}")
        session.clear()
        flash("Sesión cerrada", "info")
    return redirect('/')

# Ruta de registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        if mongo.db.usuarios.find_one({'username': username}):
            flash("El nombre de usuario ya está en uso.", "danger")
            return redirect(url_for('registro'))

        # Verificar que el correo no esté registrado
        correo = request.form['correo']
        if mongo.db.usuarios.find_one({'correo': correo}):
            flash("El correo ya está registrado.", "danger")
            return redirect(url_for('registro'))

        # Encriptar la contraseña
        hashed_password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())

        mongo.db.usuarios.insert_one({
            "username": username,
            "nombre": request.form['nombre'],
            "correo": correo,
            "telefono": request.form['telefono'],
            "password": hashed_password,
            "admin": False
        })

        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))

    return render_template('registro.html')

# Ruta de perfil
@app.route('/perfil')
def perfil():
    if 'usuario' in session:
        usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
        return render_template('perfil.html', usuario=usuario)
    return redirect('/login')

# Ruta del panel de administración
@app.route('/admin', methods=['GET'])
def admin_panel():
    if 'usuario' not in session:
        flash("Debes iniciar sesión para acceder al panel de administración", "warning")
        return redirect('/login')

    usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
    if not usuario.get('admin', False):
        flash("Acceso denegado. No eres un administrador.", "danger")
        return redirect('/')

    usuarios_comunes = mongo.db.usuarios.find({'admin': {'$ne': True}})
    productos = list(mongo.db.productos.find())

    return render_template('admin_panel.html', usuario=usuario, productos=productos, usuarios=usuarios_comunes)

# Ruta para agregar productos
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

# Ruta para ver productos
@app.route('/producto/<id>')
def ver_producto(id):
    if 'usuario' not in session:
        flash("Inicia sesión para ver productos", "warning")
        return redirect('/login')
    
    producto = mongo.db.productos.find_one({'_id': ObjectId(id)})
    if producto:
        redis_conn.zincrby("mas_vendidos", 1, producto['titulo'])
    return render_template("producto.html", producto=producto)

# Ruta para editar usuario
@app.route('/editar_usuario/<id>', methods=['GET', 'POST'])
def editar_usuario(id):
    usuario = mongo.db.usuarios.find_one({"_id": ObjectId(id)})
    
    if request.method == 'POST':
        mongo.db.usuarios.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "username": request.form['username'],
                "correo": request.form['correo'],
                "nombre": request.form['nombre'],
                "telefono": request.form['telefono']
            }}
        )
        return redirect('/admin')
    
    return render_template('editar_usuario.html', usuario=usuario)

# Ruta para eliminar usuario
@app.route('/eliminar_usuario/<id>', methods=['GET'])
def eliminar_usuario(id):
    mongo.db.usuarios.delete_one({"_id": ObjectId(id)})
    return redirect('/admin')

# Configuración de la subida de archivos
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if __name__ == '__main__':
    app.run(debug=True)

