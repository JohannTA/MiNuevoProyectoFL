import logging
import hashlib
from datetime import datetime
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

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
                   u.is_active, u.last_login, u.created_at,
                   r.name as role
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
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
    Autentica un usuario con su nombre de usuario y contraseña
    
    Args:
        username (str): Nombre de usuario
        password (str): Contraseña en texto plano
        
    Returns:
        dict: Datos del usuario si la autenticación es exitosa, None en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        # Generar hash de la contraseña
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar usuario y contraseña
            cursor.execute("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, r.name as role
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.username = %s AND u.password_hash = %s AND u.is_active = TRUE
            """, (username, password_hash))
            
            user = cursor.fetchone()
            
            if user:
                # Actualizar último login
                cursor.execute("""
                UPDATE users 
                SET last_login = NOW()
                WHERE id = %s
                """, (user['id'],))
                
                conn.commit()
            
            return user
            
    except Exception as e:
        logger.error(f"Error al autenticar usuario: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def registrar_actividad_usuario(usuario_id, accion, detalles=None, ip_address=None):
    """
    Registra una actividad realizada por un usuario
    
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
            # Solo registrar actividad en la tabla user_activity
            cursor.execute("""
            INSERT INTO user_activity (user_id, action, details, ip_address, timestamp)
            VALUES (%s, %s, %s, %s, NOW())
            """, (usuario_id, accion, detalles, ip_address))
            
            # NO actualizar last_activity en users
            
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

def listar_usuarios(filtros=None, ordenar_por='username', limit=None, offset=None):
    """
    Obtiene una lista de usuarios con opciones de filtrado y paginación
    
    Args:
        filtros (dict, optional): Diccionario con filtros para aplicar
        ordenar_por (str, optional): Campo por el que ordenar los resultados
        limit (int, optional): Cantidad máxima de resultados
        offset (int, optional): Desplazamiento para paginación
        
    Returns:
        list: Lista de usuarios
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        query = """
        SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
               u.is_active, u.last_login, u.created_at,
               r.name as role, r.id as role_id
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE 1=1
        """
        
        params = []
        
        # Aplicar filtros si existen
        if filtros:
            if 'username' in filtros and filtros['username']:
                query += " AND u.username ILIKE %s"
                params.append(f"%{filtros['username']}%")
                
            if 'email' in filtros and filtros['email']:
                query += " AND u.email ILIKE %s"
                params.append(f"%{filtros['email']}%")
                
            if 'is_active' in filtros and filtros['is_active'] is not None:
                query += " AND u.is_active = %s"
                params.append(filtros['is_active'])
                
            if 'role_id' in filtros and filtros['role_id']:
                query += " AND u.role_id = %s"
                params.append(filtros['role_id'])
        
        # Aplicar ordenamiento
        order_column = 'u.username'  # Valor por defecto
        order_valid_columns = {
            'username': 'u.username',
            'email': 'u.email',
            'first_name': 'u.first_name',
            'last_name': 'u.last_name',
            'is_active': 'u.is_active',
            'created_at': 'u.created_at',
            'last_login': 'u.last_login',
            'role': 'r.name'
        }
        
        if ordenar_por in order_valid_columns:
            order_column = order_valid_columns[ordenar_por]
            
        query += f" ORDER BY {order_column}"
        
        # Aplicar límite y offset si se especificaron
        if limit is not None:
            query += " LIMIT %s"
            params.append(limit)
            
        if offset is not None:
            query += " OFFSET %s"
            params.append(offset)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
            
    except Exception as e:
        logger.error(f"Error al listar usuarios: {e}")
        return []
    finally:
        if conn:
            conn.close()

def crear_usuario(datos, creado_por=None):
    """
    Crea un nuevo usuario en el sistema
    
    Args:
        datos (dict): Diccionario con datos del usuario
        creado_por (int, optional): ID del usuario que realiza la creación
        
    Returns:
        dict: Datos del usuario creado o None si ocurrió un error
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        # Verificar campos obligatorios
        if not datos.get('username') or not datos.get('email') or not datos.get('password') or not datos.get('role_id'):
            logger.warning("Faltan campos obligatorios para crear usuario")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar si ya existe un usuario con ese username o email
            cursor.execute("""
            SELECT 1 FROM users WHERE username = %s OR email = %s
            """, (datos['username'], datos['email']))
            
            if cursor.fetchone():
                logger.warning(f"Ya existe un usuario con username {datos['username']} o email {datos['email']}")
                return None
            
            # Verificar que el rol existe
            cursor.execute("SELECT id FROM roles WHERE id = %s", (datos['role_id'],))
            if not cursor.fetchone():
                logger.error(f"El rol ID {datos['role_id']} no existe")
                return None
            
            # Hash de la contraseña
            password_hash = hashlib.sha256(datos['password'].encode('utf-8')).hexdigest()
            
            # Insertar el nuevo usuario (sin created_by si no existe)
            cursor.execute("""
            INSERT INTO users 
            (username, email, password_hash, first_name, last_name, role_id, is_active, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
            """, (
                datos['username'],
                datos['email'],
                password_hash,
                datos.get('first_name'),
                datos.get('last_name'),
                datos['role_id'],
                datos.get('is_active', True)
            ))
            
            usuario_id = cursor.fetchone()['id']
            conn.commit()
            
            logger.info(f"Usuario creado exitosamente: ID {usuario_id}, username: {datos['username']}")
            
            # Registrar actividad
            if creado_por:
                registrar_actividad_usuario(
                    creado_por,
                    'crear_usuario',
                    f'Usuario {datos["username"]} creado con ID {usuario_id}',
                    None
                )
            
            # Devolver el usuario creado
            cursor.execute("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, u.created_at, r.name as role
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
            """, (usuario_id,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al crear usuario: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def actualizar_usuario(usuario_id, datos, actualizado_por=None):
    """
    Actualiza los datos de un usuario existente
    
    Args:
        usuario_id (int): ID del usuario a actualizar
        datos (dict): Diccionario con datos a actualizar
        actualizado_por (int, optional): ID del usuario que realiza la actualización
        
    Returns:
        bool: True si se actualizó correctamente, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (usuario_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {usuario_id}")
                return False
            
            # Verificar que el rol existe
            if datos.get('role_id'):
                cursor.execute("SELECT id FROM roles WHERE id = %s", (datos['role_id'],))
                if not cursor.fetchone():
                    logger.error(f"El rol ID {datos['role_id']} no existe")
                    return False
            
            # Actualizar usuario
            cursor.execute("""
            UPDATE users 
            SET username = %s, email = %s, first_name = %s, last_name = %s, 
                role_id = %s, is_active = %s, updated_at = NOW()
            WHERE id = %s
            """, (
                datos['username'],
                datos['email'],
                datos.get('first_name', ''),
                datos.get('last_name', ''),
                datos['role_id'],
                datos.get('is_active', True),
                usuario_id
            ))
            
            actualizado = cursor.rowcount > 0
            
            if actualizado:
                conn.commit()
                
                # Registrar actividad
                if actualizado_por:
                    registrar_actividad_usuario(
                        actualizado_por,
                        'actualizar_usuario',
                        f'Usuario ID {usuario_id} actualizado',
                        None
                    )
                
                logger.info(f"Usuario actualizado exitosamente: ID {usuario_id}")
            
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
    """
    Elimina un usuario del sistema
    
    Args:
        usuario_id (int): ID del usuario a eliminar
        
    Returns:
        bool: True si se eliminó correctamente, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (usuario_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {usuario_id}")
                return False
            
            # Eliminar usuario (soft delete o hard delete según prefieras)
            cursor.execute("DELETE FROM users WHERE id = %s", (usuario_id,))
            
            eliminado = cursor.rowcount > 0
            
            if eliminado:
                conn.commit()
                
                # Registrar actividad
                if eliminado_por:
                    registrar_actividad_usuario(
                        eliminado_por,
                        'eliminar_usuario',
                        f'Usuario {usuario_actual[0]} (ID {usuario_id}) eliminado',
                        None
                    )
                
                logger.info(f"Usuario eliminado exitosamente: ID {usuario_id}")
            
            return eliminado
            
    except Exception as e:
        logger.error(f"Error al eliminar usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def cambiar_contrasena_usuario(usuario_id, contrasena_actual, contrasena_nueva):
    """
    Cambia la contraseña de un usuario
    
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
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (usuario_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {usuario_id}")
                return False
            
            # Generar hashes
            hash_actual = hashlib.sha256(contrasena_actual.encode('utf-8')).hexdigest()
            hash_nueva = hashlib.sha256(contrasena_nueva.encode('utf-8')).hexdigest()
            
            # Verificar si la contraseña actual es correcta
            cursor.execute("""
            SELECT 1 FROM users 
            WHERE id = %s AND password_hash = %s
            """, (usuario_id, hash_actual))
            
            if not cursor.fetchone():
                logger.warning(f"Intento de cambio de contraseña con contraseña actual incorrecta para usuario ID {usuario_id}")
                return False
            
            # Actualizar la contraseña (sin password_changed_at si no existe)
            cursor.execute("""
            UPDATE users 
            SET password_hash = %s
            WHERE id = %s
            """, (hash_nueva, usuario_id))
            
            updated = cursor.rowcount > 0
            
            if updated:
                conn.commit()
                
                # Registrar actividad
                cursor.execute("""
                INSERT INTO user_activity (user_id, action, details, timestamp)
                VALUES (%s, %s, %s, NOW())
                """, (
                    usuario_id,
                    'cambiar_password',
                    "Contraseña actualizada"
                ))
                conn.commit()
            
            return updated
            
    except Exception as e:
        logger.error(f"Error al cambiar contraseña: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_actividad_usuario(usuario_id, limit=20, offset=0):
    """
    Obtiene el historial de actividad de un usuario
    
    Args:
        usuario_id (int): ID del usuario
        limit (int, optional): Límite de registros
        offset (int, optional): Desplazamiento para paginación
        
    Returns:
        list: Lista de actividades del usuario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT id, action, details, ip_address, timestamp
            FROM user_activity
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
            """, (usuario_id, limit, offset))
            
            return cursor.fetchall()
            
    except Exception as e:
        logger.error(f"Error al obtener actividad del usuario: {e}")
        return []
    finally:
        if conn:
            conn.close()

def obtener_roles():
    """
    Obtiene la lista de roles disponibles en el sistema
    
    Returns:
        list: Lista de roles
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT id, name, description
            FROM roles
            ORDER BY id
            """)
            
            return cursor.fetchall()
            
    except Exception as e:
        logger.error(f"Error al obtener roles: {e}")
        return []
    finally:
        if conn:
            conn.close()

def verificar_permiso(usuario_id, permiso):
    """
    Verifica si un usuario tiene un permiso específico
    
    Args:
        usuario_id (int): ID del usuario
        permiso (str): Nombre del permiso a verificar
        
    Returns:
        bool: True si el usuario tiene el permiso, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            cursor.execute("""
            SELECT 1
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE u.id = %s AND p.name = %s AND u.is_active = TRUE
            """, (usuario_id, permiso))
            
            return cursor.fetchone() is not None
            
    except Exception as e:
        logger.error(f"Error al verificar permiso: {e}")
        return False
    finally:
        if conn:
            conn.close()

def crear_usuario(datos, creado_por=None):
    """
    Crea un nuevo usuario en el sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor() as cursor:
            # Verificar que el rol existe
            cursor.execute("SELECT id FROM roles WHERE id = %s", (datos['role_id'],))
            if not cursor.fetchone():
                logger.error(f"El rol ID {datos['role_id']} no existe")
                return None
            
            # Hash de la contraseña
            password_hash = generate_password_hash(datos['password'])
            
            # Insertar usuario
            cursor.execute("""
            INSERT INTO users (username, email, password_hash, first_name, last_name, 
                              role_id, is_active, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
            """, (
                datos['username'],
                datos['email'],
                password_hash,
                datos.get('first_name', ''),
                datos.get('last_name', ''),
                datos['role_id'],
                datos.get('is_active', True)
            ))
            
            nuevo_id = cursor.fetchone()[0]
            conn.commit()
            
            logger.info(f"Usuario creado exitosamente: ID {nuevo_id}, username: {datos['username']}")
            
            # Registrar actividad
            if creado_por:
                registrar_actividad_usuario(
                    creado_por,
                    'crear_usuario',
                    f'Usuario {datos["username"]} creado con ID {nuevo_id}',
                    None
                )
            
            return nuevo_id
            
    except Exception as e:
        logger.error(f"Error al crear usuario: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def actualizar_usuario(user_id, datos, actualizado_por=None):
    """
    Actualiza los datos de un usuario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {user_id}")
                return False
            
            # Verificar que el rol existe
            if datos.get('role_id'):
                cursor.execute("SELECT id FROM roles WHERE id = %s", (datos['role_id'],))
                if not cursor.fetchone():
                    logger.error(f"El rol ID {datos['role_id']} no existe")
                    return False
            
            # Actualizar usuario
            cursor.execute("""
            UPDATE users 
            SET username = %s, email = %s, first_name = %s, last_name = %s, 
                role_id = %s, is_active = %s, updated_at = NOW()
            WHERE id = %s
            """, (
                datos['username'],
                datos['email'],
                datos.get('first_name', ''),
                datos.get('last_name', ''),
                datos['role_id'],
                datos.get('is_active', True),
                user_id
            ))
            
            actualizado = cursor.rowcount > 0
            
            if actualizado:
                conn.commit()
                
                # Registrar actividad
                if actualizado_por:
                    registrar_actividad_usuario(
                        actualizado_por,
                        'actualizar_usuario',
                        f'Usuario ID {user_id} actualizado',
                        None
                    )
                
                logger.info(f"Usuario actualizado exitosamente: ID {user_id}")
            
            return actualizado
            
    except Exception as e:
        logger.error(f"Error al actualizar usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def eliminar_usuario(user_id, eliminado_por=None):
    """
    Elimina un usuario del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {user_id}")
                return False
            
            # Eliminar usuario (soft delete o hard delete según prefieras)
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            
            eliminado = cursor.rowcount > 0
            
            if eliminado:
                conn.commit()
                
                # Registrar actividad
                if eliminado_por:
                    registrar_actividad_usuario(
                        eliminado_por,
                        'eliminar_usuario',
                        f'Usuario {usuario_actual[0]} (ID {user_id}) eliminado',
                        None
                    )
                
                logger.info(f"Usuario eliminado exitosamente: ID {user_id}")
            
            return eliminado
            
    except Exception as e:
        logger.error(f"Error al eliminar usuario: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def cambiar_password_usuario(user_id, nueva_password, cambiado_por=None):
    """
    Cambia la contraseña de un usuario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el usuario existe
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            usuario_actual = cursor.fetchone()
            if not usuario_actual:
                logger.warning(f"No se encontró el usuario con ID: {user_id}")
                return False
            
            # Hash de la nueva contraseña
            password_hash = generate_password_hash(nueva_password)
            
            # Actualizar contraseña
            cursor.execute("""
            UPDATE users 
            SET password_hash = %s, updated_at = NOW()
            WHERE id = %s
            """, (password_hash, user_id))
            
            actualizado = cursor.rowcount > 0
            
            if actualizado:
                conn.commit()
                
                # Registrar actividad
                if cambiado_por:
                    registrar_actividad_usuario(
                        cambiado_por,
                        'cambiar_password',
                        f'Contraseña del usuario {usuario_actual[0]} (ID {user_id}) cambiada',
                        None
                    )
                
                logger.info(f"Contraseña actualizada exitosamente para usuario ID {user_id}")
            
            return actualizado
            
    except Exception as e:
        logger.error(f"Error al cambiar contraseña: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_usuario_por_username(username):
    """
    Obtiene un usuario por su username
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return None
        
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT u.*, r.name as role_name, r.display_name as role_display_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.username = %s
            """, (username,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener usuario por username: {e}")
        return None
    finally:
        if conn:
            conn.close()

def obtener_usuario_por_email(email):
    """
    Obtiene un usuario por su email
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return None
        
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT u.*, r.name as role_name, r.display_name as role_display_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.email = %s
            """, (email,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener usuario por email: {e}")
        return None
    finally:
        if conn:
            conn.close()