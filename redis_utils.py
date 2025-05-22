import redis
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from typing import Optional, List
from flask import session, jsonify

# ------------------ CONEXIÓN REDIS ------------------ #

_r = redis.Redis(host='localhost', port=6379, decode_responses=True)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)
def get_redis_connection():
    """Devuelve la conexión Redis."""
    return _r

# ------------------ GESTIÓN DE USUARIOS ------------------ #

def guardar_usuario(username: str, password: str, admin: bool = False) -> bool:
    clave = f"usuario:{username}"
    if _r.exists(clave):
        return False  # Usuario ya existe
    usuario = {
        'username': username,
        'password': generate_password_hash(password),
        'admin': admin
    }
    _r.set(clave, json.dumps(usuario))
    return True

def obtener_usuario(username: str) -> Optional[dict]:
    clave = f"usuario:{username}"
    datos = _r.get(clave)
    try:
        return json.loads(datos) if datos else None
    except json.JSONDecodeError:
        return None

def verificar_credenciales(username: str, password: str) -> Optional[dict]:
    usuario = obtener_usuario(username)
    if usuario and check_password_hash(usuario.get('password', ''), password):
        return usuario
    return None

# ------------------ GESTIÓN DE PRODUCTOS ------------------ #

def guardar_producto(producto: dict) -> None:
    if 'id_producto' not in producto:
        raise ValueError("El producto debe tener una clave 'id_producto'")
    clave = f"producto:{producto['id_producto']}"
    _r.set(clave, json.dumps(producto))

def obtener_producto(id_producto: str) -> Optional[dict]:
    clave = f"producto:{id_producto}"
    datos = _r.get(clave)
    try:
        return json.loads(datos) if datos else None
    except json.JSONDecodeError:
        return None

def eliminar_producto(id_producto: str) -> bool:
    clave = f"producto:{id_producto}"
    return _r.delete(clave) > 0

def listar_productos() -> List[dict]:
    productos = []
    for key in _r.scan_iter("producto:*"):
        try:
            prod = _r.get(key)
            if prod:
                productos.append(json.loads(prod))
        except json.JSONDecodeError:
            continue
    return productos

# ------------------ GESTIÓN DE CARRITO ------------------ #

def agregar_producto_carrito(usuario_id: str, producto_id: str) -> int:
    return _r.sadd(f"carrito:{usuario_id}", producto_id)

def obtener_productos_carrito(usuario_id: str) -> List[str]:
    return list(_r.smembers(f"carrito:{usuario_id}"))

def quitar_producto_carrito(usuario_id: str, producto_id: str) -> int:
    return _r.srem(f"carrito:{usuario_id}", producto_id)

def vaciar_carrito(usuario_id: str) -> int:
    return _r.delete(f"carrito:{usuario_id}")

# ------------------ GESTIÓN DE WISHLIST ------------------ #

def agregar_a_wishlist(usuario_id: str, producto_id: str) -> int:
    return _r.sadd(f"wishlist:{usuario_id}", producto_id)

def quitar_de_wishlist(usuario_id: str, producto_id: str) -> int:
    return _r.srem(f"wishlist:{usuario_id}", producto_id)

def obtener_wishlist_ids(usuario_id: str) -> List[str]:
    return list(_r.smembers(f"wishlist:{usuario_id}"))

def obtener_wishlist_completa(usuario_id: str) -> List[dict]:
    productos = []
    for pid in obtener_wishlist_ids(usuario_id):
        prod = obtener_producto(pid)
        if prod:
            productos.append(prod)
    return productos

# ------------------ GESTIÓN DE COMPRAS ------------------ #

def registrar_compra(usuario_id: str, productos: List[str]) -> str:
    timestamp = datetime.now().isoformat()
    id_compra = f"{usuario_id}:{timestamp}"
    datos = {
        'usuario_id': usuario_id,
        'productos': productos,
        'fecha': timestamp
    }
    _r.set(f"compra:{id_compra}", json.dumps(datos))
    return id_compra

def obtener_compras_usuario(usuario_id: str) -> List[dict]:
    compras = []
    for key in _r.scan_iter(f"compra:{usuario_id}:*"):
        try:
            compra = _r.get(key)
            if compra:
                compras.append(json.loads(compra))
        except json.JSONDecodeError:
            continue
    return compras

def eliminar_compras_usuario(usuario_id: str) -> int:
    keys = list(_r.scan_iter(f"compra:{usuario_id}:*"))
    return _r.delete(*keys) if keys else 0

def agregar_deseo(producto_id):
    if 'usuario_id' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    usuario_id = session['usuario_id']
    clave_lista_deseos = f"deseos:{usuario_id}"

    # Verificar si el producto ya está en la lista
    if r.sismember(clave_lista_deseos, producto_id):
        return jsonify({'mensaje': 'El producto ya está en la lista de deseos'}), 200

    # Agregar el producto a la lista de deseos (conjunto en Redis)
    r.sadd(clave_lista_deseos, producto_id)

    return jsonify({'mensaje': 'Producto agregado a la lista de deseos'}), 201