from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_session import Session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt
import json
import redis
from redis.exceptions import ResponseError
import time

# --- Configuración de la App ---
app = Flask(__name__)
app.secret_key = 'clave_secreta_segura'

# Configuración de sesiones con Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379)
app.config['SESSION_PERMANENT'] = False
Session(app)

# Conexión a Redis y MongoDB
redis_conn = redis.Redis(host='localhost', port=6379, decode_responses=True)
app.config["MONGO_URI"] = "mongodb://localhost:27017/tienda_db"
mongo = PyMongo(app)

# --- Funciones auxiliares ---
def usuario_logueado():
    return 'usuario' in session

def obtener_usuario_actual():
    if usuario_logueado():
        return mongo.db.usuarios.find_one({'username': session['usuario']})
    return None

def es_admin():
    usuario = obtener_usuario_actual()
    return usuario is not None and usuario.get('admin', False)

def producto_en_lista_deseos(producto_id):
    if usuario_logueado():
        return mongo.db.deseos.find_one({'usuario_id': session['usuario_id'], 'producto_id': producto_id}) is not None
    return False

def serialize_usuario(user):
    return {
        '_id': str(user['_id']),
        'username': user['username'],
        'email': user.get('correo', ''),
        'admin': user.get('admin', False)
    }

# --- Redis TimeSeries helpers ---
def check_timeseries_module():
    try:
        redis_conn.execute_command("TS.INFO", "test_ts_temp")
    except ResponseError as err:
        if "unknown command" in str(err):
            print("RedisTimeSeries no está habilitado. Verifica tu instalación de Redis.")
            return False
        elif "does not exist" in str(err):
            pass
    return True

def create_ts_key_if_not_exists(key, retention_ms=0):
    try:
        redis_conn.execute_command("TS.CREATE", key, "RETENTION", retention_ms)
    except ResponseError as err:
        if "already exists" not in str(err):
            raise

def record_visit(page, user_type="anonymous"):
    if check_timeseries_module():
        timestamp = int(time.time() * 1000)
        key = f"visits:{page}"
        create_ts_key_if_not_exists(key)
        try:
            redis_conn.execute_command("TS.ADD", key, timestamp, 1)
            user_key = f"visits:{page}:{user_type}"
            create_ts_key_if_not_exists(user_key)
            redis_conn.execute_command("TS.ADD", user_key, timestamp, 1)
        except Exception as e:
            print(f"Error registrando visita: {e}")

# --- Hacer es_admin disponible en todas las plantillas ---
@app.context_processor
def inject_es_admin():
    return dict(es_admin=es_admin)

# --- Middleware robusto para requerir login ---
@app.before_request
def require_login():
    rutas_publicas = {
        'login', 'login_invitado', 'registro', 'static',
        'home', 'opening'
    }
    endpoint = request.endpoint
    if endpoint is None:
        return
    if endpoint in rutas_publicas or endpoint.startswith('static'):
        return
    if endpoint == 'index' and usuario_logueado():
        return
    if not usuario_logueado():
        return redirect(url_for('opening'))

# --- Página de apertura (landing) ---
@app.route('/')
def home():
    if usuario_logueado():
        return redirect(url_for('index'))
    usuario = obtener_usuario_actual()
    productos = list(mongo.db.productos.find())
    return render_template('opening.html', productos=productos, usuario=usuario)

@app.route('/opening')
def opening():
    usuario = obtener_usuario_actual()
    productos = list(mongo.db.productos.find())
    return render_template('opening.html', productos=productos, usuario=usuario)

# --- Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if usuario_logueado():
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = mongo.db.usuarios.find_one({'username': request.form['username']})
        if user and bcrypt.checkpw(request.form['password'].encode(), user['password']):
            session['usuario'] = user['username']
            session['usuario_id'] = str(user['_id'])
            redis_conn.set(f"sesion:{user['username']}", 'activa', ex=3600)
            redis_conn.hset(f"usuario:{user['username']}", 'username', user['username'])
            redis_conn.hset(f"usuario:{user['username']}", 'email', user.get('correo', ''))
            flash("Bienvenido, Administrador" if user.get('admin') else "Bienvenido", "success")
            return redirect(url_for('admin_panel' if user.get('admin') else 'index'))
        flash("Credenciales inválidas", "danger")
    usuario = obtener_usuario_actual()
    return render_template('login.html', usuario=usuario)

@app.route('/login_invitado', methods=['POST'])
def login_invitado():
    session['usuario'] = 'invitado'
    session['usuario_id'] = 'invitado'
    flash("Sesión de invitado iniciada", "info")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    usuario = session.get('usuario')
    if usuario:
        redis_conn.delete(f"sesion:{usuario}")
        redis_conn.delete(f"usuario:{usuario}")
    session.clear()
    flash("Sesión cerrada", "info")
    return redirect(url_for('opening'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if usuario_logueado():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        correo = request.form['correo']
        telefono = request.form.get('telefono', '')
        password = request.form['password']
        if mongo.db.usuarios.find_one({'username': username}):
            flash("El nombre de usuario ya existe", "danger")
            return redirect(url_for('registro'))
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        mongo.db.usuarios.insert_one({
            "username": username,
            "correo": correo,
            "telefono": telefono,
            "password": hashed_password,
            "admin": False
        })
        flash("Registro exitoso. Inicia sesión.", "success")
        return redirect(url_for('login'))
    usuario = obtener_usuario_actual()
    return render_template('registro.html', usuario=usuario)

# --- Página principal de productos con búsqueda y filtro ---
@app.route('/index')
def index():
    visitas = redis_conn.incr('visitas_index')
    user_type = "registered" if usuario_logueado() else "anonymous"
    record_visit("index", user_type)
    tipo_filtro = request.args.get('tipo')
    q = request.args.get('q', '').strip()
    query = {}
    if tipo_filtro:
        query['tipo'] = tipo_filtro
    if q:
        query['nombre'] = {'$regex': q, '$options': 'i'}
    productosventa = list(mongo.db.productos.find(query))
    usuario = obtener_usuario_actual()
    carrito, total = {}, 0
    if usuario_logueado():
        key = f"carrito:{session['usuario']}"
        carrito_raw = redis_conn.hgetall(key)
        carrito = {k: json.loads(v) for k, v in carrito_raw.items()}
        total = sum(item['cantidad'] * item['precio'] for item in carrito.values())
    return render_template('index.html',
                           productosventa=productosventa,
                           usuario=usuario,
                           carrito=carrito,
                           total=total,
                           producto_en_lista_deseos=producto_en_lista_deseos,
                           visitas=str(visitas))

# --- Perfil 

@app.route('/perfil')
def perfil():
    if not usuario_logueado():
        return redirect(url_for('login'))
    usuario = obtener_usuario_actual()

    # Asume que el usuario tiene un producto asociado (ejemplo: su producto más reciente)
    producto_id = usuario.get('producto_id')  # Asegúrate de que exista esta clave

    return render_template('perfil.html', usuario=usuario, producto_id=producto_id)


# --- Panel de administración ---
@app.route('/admin')
def admin_panel():
    if not usuario_logueado() or not es_admin():
        flash("Acceso denegado: Solo administradores.", "danger")
        return redirect(url_for('index'))
    usuarios = list(mongo.db.usuarios.find())
    productos = list(mongo.db.productos.find())
    deseos = list(mongo.db.deseos.find())
    usuario = obtener_usuario_actual()
    return render_template('admin_panel.html', usuarios=usuarios, productos=productos, deseos=deseos, usuario=usuario)

# --- Lista de deseos ---
@app.route('/deseos')
def lista_deseos():
    if not usuario_logueado():
        flash("Debe iniciar sesión para ver su lista de deseos.", "warning")
        return redirect(url_for('login'))
    deseos = list(mongo.db.deseos.find({'usuario_id': session['usuario_id']}))
    productos = []
    for deseo in deseos:
        prod = mongo.db.productos.find_one({'_id': ObjectId(deseo['producto_id'])})
        if prod:
            productos.append(prod)
    usuario = obtener_usuario_actual()
    return render_template('lista_deseos.html', productos=productos, usuario=usuario)

@app.route('/deseos/agregar/<producto_id>', methods=['POST'])
def agregar_deseo(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para agregar a la lista de deseos.", "warning")
        return redirect(url_for('login'))
    existente = mongo.db.deseos.find_one({'usuario_id': session['usuario_id'], 'producto_id': producto_id})
    if existente:
        flash("El producto ya está en su lista de deseos.", "info")
    else:
        mongo.db.deseos.insert_one({'usuario_id': session['usuario_id'], 'producto_id': producto_id})
        flash("Producto agregado a la lista de deseos.", "success")
    return redirect(request.referrer or url_for('index'))

@app.route('/deseos/eliminar/<producto_id>', methods=['POST'])
def eliminar_deseo(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para modificar su lista de deseos.", "warning")
        return redirect(url_for('login'))
    mongo.db.deseos.delete_one({'usuario_id': session['usuario_id'], 'producto_id': producto_id})
    flash("Producto eliminado de la lista de deseos.", "success")
    return redirect(request.referrer or url_for('lista_deseos'))

# --- Producto individual y métricas ---
@app.route('/producto/<producto_id>')
def ver_producto(producto_id):
    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})
    if not producto:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for('index'))

    if check_timeseries_module():
        timestamp = int(time.time() * 1000)
        product_key = f"product:views:{producto_id}"
        create_ts_key_if_not_exists(product_key)
        try:
            redis_conn.execute_command("TS.ADD", product_key, timestamp, 1)
        except Exception as e:
            print(f"Error registrando vista TS: {e}")

    usuario = obtener_usuario_actual()
    return render_template('ver_producto.html', producto=producto, usuario=usuario)

@app.route('/stats/<producto_id>')
def stats_producto(producto_id):
    if not es_admin():
        flash("Acceso restringido", "danger")
        return redirect(url_for('index'))

    now = int(time.time() * 1000)
    dia = 24 * 60 * 60 * 1000
    desde = now - dia

    vistas = []
    agregados = []

    if check_timeseries_module():
        try:
            vistas = redis_conn.execute_command("TS.RANGE", f"product:views:{producto_id}", desde, now)
            agregados = redis_conn.execute_command("TS.RANGE", f"product:cart_adds:{producto_id}", desde, now)
        except Exception as e:
            flash(f"Error obteniendo métricas TS: {e}", "danger")

    usuario = obtener_usuario_actual()
    return render_template('stats_producto.html', vistas=vistas, agregados=agregados, producto_id=producto_id, usuario=usuario)

# --- Carrito de compras ---
@app.route('/carrito')
def ver_carrito():
    if not usuario_logueado():
        flash("Debe iniciar sesión para ver su carrito.", "warning")
        return redirect(url_for('login'))
    key = f"carrito:{session['usuario']}"
    carrito_raw = redis_conn.hgetall(key)
    carrito = {k: json.loads(v) for k, v in carrito_raw.items()}
    total = sum(item['cantidad'] * item['precio'] for item in carrito.values())
    usuario = obtener_usuario_actual()
    return render_template('carrito.html', carrito=carrito, total=total, usuario=usuario)

@app.route('/carrito/agregar/<producto_id>', methods=['POST'])
def agregar_carrito(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para agregar productos al carrito.", "warning")
        return redirect(url_for('login'))

    producto = mongo.db.productos.find_one({'_id': ObjectId(producto_id)})
    if not producto:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for('index'))

    cantidad = int(request.form.get('cantidad', 1))
    if cantidad < 1:
        flash("Cantidad inválida.", "warning")
        return redirect(request.referrer or url_for('index'))

    key = f"carrito:{session['usuario']}"
    carrito_raw = redis_conn.hgetall(key)
    carrito = {k: json.loads(v) for k, v in carrito_raw.items()}

    if producto_id in carrito:
        carrito[producto_id]['cantidad'] += cantidad
    else:
        carrito[producto_id] = {
            'nombre': producto['nombre'],
            'precio': producto['precio'],
            'cantidad': cantidad
        }
    redis_conn.hset(key, producto_id, json.dumps(carrito[producto_id]))
    flash(f"Producto '{producto['nombre']}' agregado al carrito.", "success")

    if check_timeseries_module():
        timestamp = int(time.time() * 1000)
        cart_key = f"product:cart_adds:{producto_id}"
        create_ts_key_if_not_exists(cart_key)
        try:
            redis_conn.execute_command("TS.ADD", cart_key, timestamp, 1)
        except Exception as e:
            print(f"Error registrando agregado al carrito TS: {e}")

    return redirect(request.referrer or url_for('index'))

@app.route('/carrito/eliminar/<producto_id>', methods=['POST'])
def eliminar_carrito(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para modificar el carrito.", "warning")
        return redirect(url_for('login'))
    key = f"carrito:{session['usuario']}"
    redis_conn.hdel(key, producto_id)
    flash("Producto eliminado del carrito.", "success")
    return redirect(request.referrer or url_for('ver_carrito'))

@app.route('/carrito/limpiar', methods=['POST'])
def limpiar_carrito():
    if not usuario_logueado():
        flash("Debe iniciar sesión para limpiar el carrito.", "warning")
        return redirect(url_for('login'))
    key = f"carrito:{session['usuario']}"
    redis_conn.delete(key)
    flash("Carrito limpiado.", "success")
    return redirect(url_for('ver_carrito'))

# --- Vender producto ---
@app.route('/vender', methods=['GET', 'POST'])
def vender():
    if not usuario_logueado():
        flash("Debes iniciar sesión para vender productos.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        usuario = obtener_usuario_actual()
        producto = {
            "nombre": request.form.get('titulo'),
            "precio": float(request.form.get('precio', 0)),
            "descripcion": request.form.get('descripcion', ''),
            "tipo": request.form.get('tipo', ''),
            "imagen": request.form.get('imagen', ''),
            "usuario_id": usuario['_id'],
            "vendido": False
        }
        mongo.db.productos.insert_one(producto)
        flash("Producto añadido para la venta", "success")
        return redirect(url_for('index'))
    usuario = obtener_usuario_actual()
    return render_template('vender.html', usuario=usuario)

# --- Mis productos ---
@app.route('/mis_productos')
def mis_productos():
    if not usuario_logueado():
        return redirect(url_for('login'))
    usuario_id = session.get('usuario_id')
    productos = list(mongo.db.productos.find({'usuario_id': usuario_id}))
    usuario = obtener_usuario_actual()
    return render_template('mis_productos.html', productos=productos, usuario=usuario)

# --- API: Obtener usuario actual ---
@app.route('/api/usuario_actual')
def usuario_actual_api():
    if not usuario_logueado():
        return jsonify({'error': 'Usuario no autenticado'}), 401
    usuario = obtener_usuario_actual()
    return jsonify(serialize_usuario(usuario))

# --- Manejo de errores ---
@app.errorhandler(404)
def pagina_no_encontrada(error):
    usuario = obtener_usuario_actual()
    return render_template('404.html', usuario=usuario), 404

@app.errorhandler(500)
def error_interno(error):
    usuario = obtener_usuario_actual()
    return render_template('500.html', usuario=usuario), 500

@app.route('/stats/<int:producto_id>')
def stats_productos(producto_id):
    return render_template('stats_productos.html', producto_id=producto_id)


if __name__ == '__main__':
    app.run(debug=True)
