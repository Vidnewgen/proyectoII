from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_pymongo import PyMongo
from flask_session import Session
from redis import Redis
from bson.objectid import ObjectId

import bcrypt
import json

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
    productosventa = list(mongo.db.productos.find())
    usuario = mongo.db.usuarios.find_one({'username': session.get('usuario')}) if 'usuario' in session else None
    productos_carrito = []  # Inicializamos la lista vacía para los productos del carrito
    total = 0  # Inicializamos el total

    if 'usuario' in session:  # Solo mostramos el carrito si el usuario está autenticado
        carrito_key = f"carrito:{session['usuario']}"

        # Recuperamos todos los productos del carrito en Redis (hash)
        productos_carrito = redis_conn.hgetall(carrito_key)
        # Convertimos los productos de Redis (JSON) a diccionarios de Python
        productos_carrito = {k: json.loads(v) for k, v in productos_carrito.items()}
        # Totalizamos el precio del carrito
        total = sum([producto['cantidad'] * producto['precio'] for producto in productos_carrito.values()])
    print(productos_carrito)
    return render_template('index.html', productosventa=productosventa, usuario=usuario, carrito=productos_carrito, total=total)

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = mongo.db.usuarios.find_one({
            'username': request.form['username']
        })
        
        if user and bcrypt.checkpw(request.form['password'].encode('utf-8'), user['password']):
            session['usuario'] = user['username']
            session['usuario_id'] = str(user['_id'])  # Guardar el usuario_id en la sesión

            redis_conn.set(f"sesion:{user['username']}", 'activa', ex=3600)  # Expira en 1 hora
            redis_conn.hmset(f"usuario:{user['username']}", {
                'username': user['username'],
                'email': user.get('correo', ''),
                'nombre': user.get('nombre', '')
            })

            flash("Bienvenido, Administrador" if user.get('admin', False) else "Bienvenido", "success")
            return redirect(url_for('admin_panel' if user.get('admin', False) else 'index'))


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
        # Obtener los datos del formulario
        username = request.form['username']
        correo = request.form['correo']
        password = request.form['password']
        telefono = request.form['telefono']
        
        # Encriptar la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insertar el usuario en la base de datos
        mongo.db.usuarios.insert_one({
            "username": username,
            "correo": correo,
            "password": hashed_password,
            "telefono": telefono,
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

# AGREGAR CARRITO
@app.route('/agregar_al_carrito/<producto_id>', methods=['POST'])
def agregar_al_carrito(producto_id):
    if 'usuario' not in session:
        flash("Debes iniciar sesión para agregar productos al carrito", "warning")
        return redirect('/login')

    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})
    if not producto:
        flash("Producto no encontrado", "danger")
        return redirect('/')

    usuario = session['usuario']
    carrito_key = f"carrito:{usuario}"

    # Verificar si la clave ya existe y tiene un tipo incorrecto
    if redis_conn.exists(carrito_key):
        if redis_conn.type(carrito_key) != 'hash':
            # Si la clave no es un hash, la eliminamos para evitar el error
            redis_conn.delete(carrito_key)

    # Crear el objeto del producto a agregar al carrito
    producto_data = {
        "producto_id": producto_id,
        "nombre": producto['titulo'],
        "cantidad": 1,  # Inicializamos con una cantidad de 1
        "precio": producto['precio']  # Suponiendo que el producto tiene un campo 'precio'
    }

    # Usamos HSET para agregar el producto al carrito, la clave del hash es el producto_id
    redis_conn.hset(carrito_key, producto_id, json.dumps(producto_data))

    # Establecer un TTL de 1 hora (3600 segundos)
    redis_conn.expire(carrito_key, 3600)

    flash("Producto agregado al carrito", "success")
    return redirect(url_for('index'))


# ELIMINAR ITEM CARRITO
@app.route('/eliminar_del_carrito/<producto_id>', methods=['GET', 'POST'])
def eliminar_del_carrito(producto_id):
    if 'usuario' not in session:
        flash("Debes iniciar sesión para modificar el carrito", "warning")
        return redirect('/login')

    usuario = session['usuario']
    carrito_key = f"carrito:{usuario}"
    print (carrito_key)
    if redis_conn.hexists(carrito_key, producto_id):
        redis_conn.hdel(carrito_key, producto_id)
        flash("Producto eliminado del carrito", "success")
    else:
        flash("Producto no encontrado en el carrito", "info")

    return redirect(request.referrer or url_for('index'))

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

# VENDER
@app.route('/vender', methods=['GET', 'POST'])
def vender_producto():
    if 'usuario' in session:  # Verificamos si el usuario está logueado
        usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
        
        if request.method == 'POST':
            tipo = request.form['tipo']
            precio = float(request.form['precio'])
            titulo = request.form['titulo']
            descripcion = request.form['descripcion']
            imagen = request.form['imagen']  # Puede ser un URL o nombre de archivo si quieres subir imágenes.

            # Obtener el ID del usuario que está publicando el producto (esto puede ser a través de la sesión).
            usuario_id = str(usuario['_id'])  # Usamos el _id del usuario logueado

            # Guardar el producto en la base de datos
            mongo.db.productos.insert_one({
                "tipo": tipo,
                "precio": precio,
                "titulo": titulo,
                "descripcion": descripcion,
                "imagen": imagen,
                "usuario_id": usuario_id  # Asociamos el producto con el usuario que lo publica
            })
            return redirect('/mis_productos')  # Redirigir a la página de productos del usuario

        return render_template('vender.html', usuario=usuario)  # Pasar el usuario a la plantilla
    
    flash("Debes iniciar sesión para vender productos", "warning")
    return redirect('/login')


#MIS Productos
@app.route('/mis_productos')
def mis_productos():
    if 'usuario' in session:  # Verificamos si hay un usuario en sesión
        usuario = mongo.db.usuarios.find_one({'username': session['usuario']})
        
        # Obtener los productos del usuario logueado
        productos = mongo.db.productos.find({"usuario_id": str(usuario['_id'])})
        
        return render_template('mis_productos.html', productos=productos, usuario=usuario)
    
    flash("Debes iniciar sesión para ver tus productos", "warning")
    return redirect('/login')

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

#agregar a lalista de deseos
@app.route('/agregar_deseo_mongo/<id>', methods=['POST'])
def agregar_deseo_mongo(id):
    if not usuario_logueado():
        flash("Inicia sesión para agregar a tu lista de deseos", "warning")
        return redirect(url_for('login'))

    producto = mongo.db.productos.find_one({"_id": ObjectId(id)})
    if not producto:
        flash("Producto no encontrado", "danger")
        return redirect(url_for('index'))

    usuario = mongo.db.usuarios.find_one({"_id": ObjectId(session['usuario_id'])})
    if usuario:
        if not mongo.db.deseos.find_one({'usuario_id': session['usuario_id'], 'producto_id': id}):
            mongo.db.deseos.insert_one({
                'usuario_id': session['usuario_id'],
                'producto_id': id,
                'nombre': producto.get('nombre', ''),
                'imagen': producto.get('imagen', '')
            })
            flash("Producto agregado a tu lista de deseos", "success")
        else:
            flash("Este producto ya está en tu lista de deseos", "info")
    return redirect(url_for('index'))

#eliminar deseos
@app.route('/eliminar_deseo_mongo/<id>', methods=['POST'])
def eliminar_deseo_mongo(id):
    if not usuario_logueado():
        flash("Inicia sesión para eliminar de tu lista de deseos", "warning")
        return redirect(url_for('login'))

    producto = mongo.db.productos.find_one({"_id": ObjectId(id)})
    if not producto:
        flash("Producto no encontrado", "danger")
        return redirect(url_for('index'))

    resultado = mongo.db.deseos.delete_one({'usuario_id': session['usuario_id'], 'producto_id': id})
    if resultado.deleted_count > 0:
        flash("Producto eliminado de tu lista de deseos", "success")
    else:
        flash("Este producto no estaba en tu lista de deseos", "info")
    return redirect(url_for('lista_deseos'))

#lista de deseos
@app.route('/lista_deseos')
def lista_deseos():
    if not usuario_logueado():
        flash("Inicia sesión para ver tu lista", "warning")
        return redirect(url_for('login'))

    deseos = list(mongo.db.deseos.find({'usuario_id': session['usuario_id']}))
    return render_template('lista_deseos.html', deseos=deseos, titulo='Mis Deseos')

# Configuración de la subida de archivos
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def usuario_logueado():
    return 'usuario' in session

if __name__ == '__main__':
    app.run(debug=True)
