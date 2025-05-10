# redis_utils.py
import redis
import json
from werkzeug.security import generate_password_hash, check_password_hash

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def guardar_usuario(username, password, admin=False):
    clave = f"usuario:{username}"
    if r.exists(clave):
        return False  # Usuario ya existe
    usuario = {
        'username': username,
        'password': generate_password_hash(password),
        'admin': admin
    }
    r.set(clave, json.dumps(usuario))
    return True

def obtener_usuario(username):
    clave = f"usuario:{username}"
    datos = r.get(clave)
    if datos:
        return json.loads(datos)
    return None

def verificar_credenciales(username, password):
    usuario = obtener_usuario(username)
    if usuario and check_password_hash(usuario['password'], password):
        return usuario
    return None
