from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_session import Session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt
import json
import redis
from redis.exceptions import ResponseError
import time
from redis_utils import obtener_producto, actualizar_producto
from datetime import datetime

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
    return 'usuario' in session and session['usuario'] != 'invitado'

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

def record_visit(page, user_type):
    key = f"visita:{page}:{user_type}"
    redis_conn.incr(key)

def check_timeseries_module():
    try:
        redis_conn.execute_command('TS.INFO', 'dummy_key')
        return True
    except ResponseError:
        return False

def create_ts_key_if_not_exists(key):
    try:
        redis_conn.execute_command("TS.CREATE", key, "RETENTION", 604800000)
    except redis.exceptions.ResponseError as e:
        if "already exists" not in str(e):
            raise

# --- Middleware robusto para requerir login ---
@app.before_request
def require_login():
    rutas_publicas = {'login', 'login_invitado', 'registro', 'static', 'home', 'opening', 'logout'}
    endpoint = request.endpoint
    if endpoint is None:
        return
    if endpoint in rutas_publicas or endpoint.startswith('static'):
        return
    if not usuario_logueado() and endpoint not in {'index', 'login', 'registro'}:
        return redirect(url_for('opening'))

# --- Rutas de la Aplicación ---

# Página de apertura (landing)
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
    user_type = "registered" if usuario_logueado() else "anonymous"
    visitas = redis_conn.incr('visitas_index')
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

    if user_type == "anonymous":
        return render_template('index_invitado.html', productosventa=productosventa, visitas=str(visitas))

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
                           visitas=str(visitas))

# --- Perfil ---
@app.route('/perfil')
def perfil():
    if not usuario_logueado():
        return redirect(url_for('login'))
    usuario = obtener_usuario_actual()
    producto_id = usuario.get('producto_id')
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
        mongo.db.deseos.insert_one({
            'usuario_id': session['usuario_id'],
            'producto_id': producto_id
        })
        flash("Producto agregado a la lista de deseos.", "success")
    return redirect(url_for('index'))

@app.route('/deseos/eliminar/<producto_id>', methods=['POST'])
def eliminar_deseo(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para modificar la lista de deseos.", "warning")
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

# --- Estadísticas de productos ---
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

# Definir las colecciones de MongoDB
carritos_collection = mongo.db.carritos  # Asegúrate de que esto esté definido
deseos_collection = mongo.db.deseos      # Asegúrate de que esto esté definido


@app.route('/carrito')
def ver_carrito():
    if not usuario_logueado():
        flash("Debe iniciar sesión para ver su carrito.", "warning")
        return redirect(url_for('login'))
    
    user_id = session['usuario_id']  # Usar 'usuario_id' para consistencia
    key = f"carrito:{user_id}"
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

    user_id = session['usuario_id']
    key = f"carrito:{user_id}"
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

    return redirect(request.referrer or url_for('index'))


@app.route('/carrito/eliminar/<producto_id>', methods=['POST'])
def eliminar_carrito(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para modificar el carrito.", "warning")
        return redirect(url_for('login'))
    
    user_id = session['usuario_id']
    key = f"carrito:{user_id}"
    redis_conn.hdel(key, producto_id)
    flash("Producto eliminado del carrito.", "success")
    return redirect(request.referrer or url_for('ver_carrito'))

@app.route('/vaciar_carrito', methods=['POST'])
def vaciar_carrito():
    try:
        # Verificar autenticación con cualquiera de las dos claves posibles
        user_id = session.get('user_id') or session.get('usuario_id')
        if not user_id:
            flash("Debe iniciar sesión para limpiar el carrito.", "warning")
            return redirect(url_for('login'))

        # Eliminar carrito en Redis (si usas Redis)
        key = f"carrito:{user_id}"
        redis_deleted = False
        if 'redis_conn' in globals():
            redis_deleted = redis_conn.delete(key)  # devuelve número de claves eliminadas

        # Eliminar carrito en MongoDB (si usas MongoDB)
        mongo_deleted_count = 0
        if 'carritos_collection' in globals():
            resultado = carritos_collection.delete_many({'user_id': user_id})
            mongo_deleted_count = resultado.deleted_count

        # Construir mensaje de resultado
        mensajes = []
        if redis_deleted:
            mensajes.append("Carrito en Redis limpiado.")
        if mongo_deleted_count > 0:
            mensajes.append(f"Se eliminaron {mongo_deleted_count} productos del carrito.")
        if not mensajes:
            mensajes.append("El carrito ya estaba vacío.")

        flash(" ".join(mensajes), "success")
        return redirect(url_for('ver_carrito'))

    except Exception as e:
        flash(f"Error al vaciar el carrito: {str(e)}", "error")
        return redirect(url_for('ver_carrito'))



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
            "usuario_id": str(usuario['_id']),
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
        flash("Debe iniciar sesión para ver sus productos.", "warning")
        return redirect(url_for('login'))
    productos = list(mongo.db.productos.find({'usuario_id': session['usuario_id']}))
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
    return render_template('404.html', usuario=usuario), 500

# --- Registro de funciones para templates ---
@app.context_processor
def inject_global_functions():
    return {
        'es_admin': es_admin,
        'usuario_logueado': usuario_logueado,
        'obtener_usuario_actual': obtener_usuario_actual,
        'producto_en_lista_deseos': producto_en_lista_deseos
    }

@app.route('/editar_producto/<producto_id>', methods=['GET', 'POST'])
def editar_producto(producto_id):
    if not usuario_logueado():
        flash("Debe iniciar sesión para editar productos.", "warning")
        return redirect(url_for('login'))

    producto = obtener_producto(producto_id)
    if not producto:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for('index'))

    # Opcional: verifica que el usuario sea dueño o admin para editar
    if not es_admin() and producto.get('usuario_id') != session.get('usuario_id'):
        flash("No tienes permisos para editar este producto.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        imagen = request.form.get('imagen', '').strip()

        if not nombre or not descripcion or not imagen:
            flash("Todos los campos son obligatorios.", "warning")
            return render_template('editar_producto.html', producto=producto)

        datos_actualizados = {
            'nombre': nombre,
            'descripcion': descripcion,
            'imagen': imagen
        }

        exito = actualizar_producto(producto_id, datos_actualizados)
        if exito:
            flash("Producto actualizado correctamente.", "success")
            return redirect(url_for('perfil'))  # O la página que quieras
        else:
            flash("Error al actualizar el producto.", "danger")

    return render_template('editar_producto.html', producto=producto)


@app.route('/actualizar_cantidad_carrito/<item_id>', methods=['POST'])
def actualizar_cantidad_carrito(item_id):
    try:
        user_id = session.get('user_id') or session.get('usuario_id')
        if not user_id:
            return redirect(url_for('login'))

        accion = request.form.get('accion')

        item = carritos_collection.find_one({
            '_id': ObjectId(item_id),
            'user_id': user_id
        })

        if not item:
            flash('Producto no encontrado en el carrito', 'error')
            return redirect(url_for('ver_carrito'))

        if accion == 'incrementar':
            carritos_collection.update_one(
                {'_id': ObjectId(item_id)},
                {'$inc': {'cantidad': 1}}
            )
            flash('Cantidad incrementada', 'success')

        elif accion == 'decrementar':
            if item['cantidad'] > 1:
                carritos_collection.update_one(
                    {'_id': ObjectId(item_id)},
                    {'$inc': {'cantidad': -1}}
                )
                flash('Cantidad decrementada', 'success')
            else:
                flash('La cantidad mínima es 1', 'warning')

        return redirect(url_for('ver_carrito'))

    except Exception as e:
        flash(f'Error al actualizar cantidad: {str(e)}', 'error')
        return redirect(url_for('ver_carrito'))


@app.route('/vaciar_deseos', methods=['POST'])
def vaciar_deseos():
    try:
        user_id = session.get('user_id') or session.get('usuario_id')
        if not user_id:
            return redirect(url_for('login'))

        resultado = deseos_collection.delete_many({'user_id': user_id})
        
        if resultado.deleted_count > 0:
            flash(f'Se eliminaron {resultado.deleted_count} productos de la lista de deseos', 'success')
        else:
            flash('La lista de deseos ya estaba vacía', 'info')
        
        return redirect(url_for('lista_deseos'))

    except Exception as e:
        flash(f'Error al vaciar la lista de deseos: {str(e)}', 'error')
        return redirect(url_for('lista_deseos'))


@app.route('/agregar_todos_carrito', methods=['POST'])
def agregar_todos_carrito():
    try:
        # Verificar que el usuario esté autenticado
        if 'user_id' not in session and 'usuario_id' not in session:
            flash("Debes iniciar sesión para agregar productos al carrito.", "warning")
            return redirect(url_for('login'))

        # Obtener user_id de la sesión (considerando ambos nombres posibles)
        user_id = session.get('user_id') or session.get('usuario_id')

        # Intentar obtener productos desde la lista de deseos en MongoDB
        deseos_items = list(deseos_collection.find({'user_id': user_id}))

        if deseos_items:
            # Agregar productos desde la lista de deseos (MongoDB)
            contador_agregados = 0
            for deseo in deseos_items:
                carrito_existente = carritos_collection.find_one({
                    'user_id': user_id,
                    'producto_id': deseo['producto_id']
                })

                if carrito_existente:
                    # Incrementar cantidad si ya existe
                    carritos_collection.update_one(
                        {'_id': carrito_existente['_id']},
                        {'$inc': {'cantidad': 1}}
                    )
                else:
                    # Insertar nuevo producto en carrito
                    carritos_collection.insert_one({
                        'user_id': user_id,
                        'producto_id': deseo['producto_id'],
                        'nombre_producto': deseo.get('nombre_producto', ''),
                        'precio': deseo.get('precio', 0),
                        'imagen': deseo.get('imagen', ''),
                        'cantidad': 1
                    })
                contador_agregados += 1

            if contador_agregados > 0:
                flash(f'Se agregaron {contador_agregados} productos desde la lista de deseos al carrito.', 'success')
            else:
                flash('No hay productos en la lista de deseos para agregar.', 'info')

            return redirect(url_for('lista_deseos'))

        else:
            # Si no hay productos en lista de deseos, agregar todos los productos disponibles desde SQLAlchemy
            productos = producto.query.all()

            if not productos:
                flash('No hay productos disponibles para agregar.', 'warning')
                return redirect(url_for('tienda'))

            for producto in productos:
                carrito_item = Carrito.query.filter_by(user_id=user_id, producto_id=producto.id).first()
                if carrito_item:
                    carrito_item.cantidad += 1
                else:
                    nuevo_item = Carrito(user_id=user_id, producto_id=producto.id, cantidad=1)
                    db.session.add(nuevo_item)

            db.session.commit()
            flash('Todos los productos disponibles han sido agregados a tu carrito.', 'success')
            return redirect(url_for('carrito'))

    except Exception as e:
        # Manejo de errores general
        flash(f'Ocurrió un error al agregar los productos al carrito: {str(e)}', 'danger')
        # Redirigir según el contexto, aquí a tienda por defecto
        return redirect(url_for('tienda'))




# Función para obtener el contador del carrito (opcional, para mostrar en navbar)
@app.context_processor
def inject_cart_count():
    cart_count = 0
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            carrito_items = carritos_collection.find({'user_id': user_id})
            cart_count = sum(item.get('cantidad', 1) for item in carrito_items)
        except:
            cart_count = 0
    return dict(cart_count=cart_count)

# Función para obtener el contador de deseos (opcional, para mostrar en navbar)
@app.context_processor
def inject_wishlist_count():
    wishlist_count = 0
    if 'user_id' in session:
        try:
            user_id = session['user_id']
            wishlist_count = deseos_collection.count_documents({'user_id': user_id})
        except:
            wishlist_count = 0
    return dict(wishlist_count=wishlist_count)

# --- Punto de entrada de la aplicación ---
if __name__ == '__main__':
    app.run(debug=True)
