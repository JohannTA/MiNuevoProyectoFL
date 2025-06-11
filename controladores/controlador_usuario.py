import logging
import hashlib
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def hash_password_sha256(password):
    """Genera hash SHA-256 para una contraseña"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def obtener_usuario_por_id(usuario_id):
    """
    Obtiene un usuario por su ID
    
    Args:
        usuario_id (int): ID del usuario
        
    Returns:
        dict: Datos del usuario o None si no existe
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, u.last_login, u.created_at, u.password_hash,
                   r.name as role, r.display_name as role_display_name,
                   r.id as role_id, u.failed_login_attempts, u.locked_until
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
            """, (usuario_id,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener usuario por ID: {e}")
        return None
    finally:
        if conn:
            conn.close()

def autenticar_usuario(username, password):
    """
    Autentica un usuario con su nombre de usuario y contraseña usando SHA-256
    
    Args:
        username (str): Nombre de usuario
        password (str): Contraseña en texto plano
        
    Returns:
        dict: Datos del usuario si la autenticación es exitosa, None en caso contrario
    """
    conn = None
    try:
        if not username or not password:
            logger.warning("Intento de autenticación con credenciales vacías")
            return None
            
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        # Generar hash SHA-256 de la contraseña
        password_hash = hash_password_sha256(password)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Buscar usuario activo
            cursor.execute("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, u.password_hash, u.failed_login_attempts, u.locked_until,
                   r.name as role, r.display_name as role_display_name,
                   r.id as role_id
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.username = %s AND u.is_active = TRUE
            """, (username,))
            
            user = cursor.fetchone()
            
            # Log para debug
            logger.info(f"Buscando usuario: {username}")
            if user:
                logger.info(f"Usuario encontrado: {user['username']}")
                logger.info(f"Hash almacenado: {user['password_hash']}")
                logger.info(f"Hash generado: {password_hash}")
                logger.info(f"Coinciden: {user['password_hash'] == password_hash}")
                
                # Verificar si está bloqueado
                if user['locked_until'] and user['locked_until'] > datetime.now():
                    logger.warning(f"Usuario bloqueado hasta: {user['locked_until']}")
                    return None
            else:
                logger.warning(f"Usuario no encontrado o inactivo: {username}")
                return None
            
            # Verificar contraseña
            if user['password_hash'] == password_hash:
                logger.info(f"Autenticación exitosa para usuario: {username}")
                
                # Resetear intentos fallidos y actualizar último login
                cursor.execute("""
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, 
                    failed_login_attempts = 0,
                    locked_until = NULL
                WHERE id = %s
                """, (user['id'],))
                conn.commit()
                
                return dict(user)
            else:
                # Incrementar intentos fallidos
                failed_attempts = (user['failed_login_attempts'] or 0) + 1
                locked_until = None
                
                if failed_attempts >= 5:  # Bloquear después de 5 intentos
                    locked_until = datetime.now() + timedelta(minutes=15)
                    logger.warning(f"Usuario bloqueado por 15 minutos: {username}")
                
                cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = %s, locked_until = %s
                WHERE id = %s
                """, (failed_attempts, locked_until, user['id']))
                conn.commit()
                
                logger.warning(f"Contraseña incorrecta para usuario: {username} (Intento {failed_attempts})")
                return None
                
    except Exception as e:
        logger.error(f"Error en autenticación: {e}")
        return None
    finally:
        if conn:
            conn.close()

def registrar_actividad_usuario(usuario_id, accion, detalles=None, ip_address=None):
    """
    Registra una actividad realizada por un usuario en activity_logs
    
    Args:
        usuario_id (int): ID del usuario
        accion (str): Nombre de la acción realizada
        detalles (str, optional): Detalles adicionales
        ip_address (str, optional): Dirección IP del usuario
        
    Returns:
        bool: True si se registró correctamente, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO activity_logs (user_id, action, details, ip_address, timestamp)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (usuario_id, accion, detalles, ip_address))
            
            conn.commit()
            return True
            
    except Exception as e:
        logger.error(f"Error al registrar actividad de usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def cambiar_contrasena_usuario(usuario_id, contrasena_actual, contrasena_nueva):
    """
    Cambia la contraseña de un usuario usando SHA-256
    
    Args:
        usuario_id (int): ID del usuario
        contrasena_actual (str): Contraseña actual
        contrasena_nueva (str): Nueva contraseña
        
    Returns:
        bool: True si se cambió correctamente, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar contraseña actual
            hash_actual = hash_password_sha256(contrasena_actual)
            cursor.execute("""
            SELECT 1 FROM users 
            WHERE id = %s AND password_hash = %s
            """, (usuario_id, hash_actual))
            
            if not cursor.fetchone():
                logger.warning(f"Contraseña actual incorrecta para usuario ID {usuario_id}")
                return False
            
            # Actualizar contraseña
            hash_nueva = hash_password_sha256(contrasena_nueva)
            cursor.execute("""
            UPDATE users 
            SET password_hash = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """, (hash_nueva, usuario_id))
            
            updated = cursor.rowcount > 0
            
            if updated:
                conn.commit()
                logger.info(f"Contraseña actualizada para usuario ID {usuario_id}")
            
            return updated
            
    except Exception as e:
        logger.error(f"Error al cambiar contraseña: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def listar_usuarios(filtros=None, ordenar_por='username', limit=None, offset=None):
    """Obtiene lista de usuarios con información de roles"""
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, u.last_login, u.created_at, u.failed_login_attempts,
                   r.name as role, r.display_name as role_display_name,
                   r.id as role_id
            FROM users u
            JOIN roles r ON u.role_id = r.id
            ORDER BY u.username
            """)
            return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error al listar usuarios: {e}")
        return []
    finally:
        if conn:
            conn.close()

def crear_usuario(datos, creado_por=None):
    """Crea un nuevo usuario con hash SHA-256"""
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return None
        
        password_hash = hash_password_sha256(datos['password'])
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            INSERT INTO users (username, email, password_hash, first_name, last_name, 
                              role_id, is_active, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            RETURNING id
            """, (
                datos['username'], datos['email'], password_hash,
                datos.get('first_name', ''), datos.get('last_name', ''),
                datos.get('role_id'), datos.get('is_active', True)
            ))
            
            nuevo_id = cursor.fetchone()['id']
            conn.commit()
            return nuevo_id
            
    except Exception as e:
        logger.error(f"Error al crear usuario: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def actualizar_usuario(usuario_id, datos, actualizado_por=None):
    """Actualiza un usuario"""
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return False
        
        with conn.cursor() as cursor:
            cursor.execute("""
            UPDATE users 
            SET username = %s, email = %s, first_name = %s, last_name = %s, 
                role_id = %s, is_active = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """, (
                datos['username'], datos['email'], 
                datos.get('first_name', ''), datos.get('last_name', ''),
                datos.get('role_id'), datos.get('is_active', True),
                usuario_id
            ))
            
            actualizado = cursor.rowcount > 0
            if actualizado:
                conn.commit()
            return actualizado
            
    except Exception as e:
        logger.error(f"Error al actualizar usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def eliminar_usuario(usuario_id, eliminado_por=None):
    """Elimina un usuario"""
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return False
        
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id = %s", (usuario_id,))
            eliminado = cursor.rowcount > 0
            if eliminado:
                conn.commit()
            return eliminado
            
    except Exception as e:
        logger.error(f"Error al eliminar usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()