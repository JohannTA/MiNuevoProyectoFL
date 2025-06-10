import logging
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

logger = logging.getLogger(__name__)

def obtener_roles():
    """
    Obtiene todos los roles del sistema usando tu estructura actual
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT 
                r.id,
                r.name,
                r.display_name,
                r.description,
                r.created_at,
                COUNT(DISTINCT u.id) as user_count,
                COUNT(DISTINCT rp.permission_id) as permission_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id AND u.is_active = TRUE
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            GROUP BY r.id, r.name, r.display_name, r.description, r.created_at
            ORDER BY r.id
            """)
            
            roles = cursor.fetchall()
            logger.info(f"Se obtuvieron {len(roles)} roles")
            return roles
            
    except Exception as e:
        logger.error(f"Error al obtener roles: {e}")
        return []
    finally:
        if conn:
            conn.close()
def obtener_rol_por_id(role_id):
    """
    Obtiene un rol específico por su ID
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT 
                r.id,
                r.name,
                r.name as display_name,
                r.description,
                r.created_at,
                COUNT(DISTINCT u.id) as user_count
            FROM roles r
            LEFT JOIN users u ON r.id = u.role_id AND u.is_active = TRUE
            WHERE r.id = %s
            GROUP BY r.id, r.name, r.description, r.created_at
            """, (role_id,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener rol por ID: {e}")
        return None
    finally:
        if conn:
            conn.close()

def obtener_permisos():
    """
    Obtiene todos los permisos del sistema con información adicional
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT 
                p.id,
                p.name,
                p.description,
                'general' as module,
                p.name as display_name,
                COALESCE(COUNT(rp.role_id), 0) as role_count
            FROM permissions p
            LEFT JOIN role_permissions rp ON p.id = rp.permission_id
            GROUP BY p.id, p.name, p.description
            ORDER BY p.name
            """)
            
            permisos = cursor.fetchall()
            
            # Convertir a lista de diccionarios con role_count como entero
            permisos_lista = []
            for permiso in permisos:
                permiso_dict = dict(permiso)
                permiso_dict['role_count'] = int(permiso_dict['role_count'] or 0)
                permisos_lista.append(permiso_dict)
            
            logger.info(f"Se obtuvieron {len(permisos_lista)} permisos")
            return permisos_lista
            
    except Exception as e:
        logger.error(f"Error al obtener permisos: {e}")
        return []
    finally:
        if conn:
            conn.close()
def obtener_permisos_rol(role_id):
    """
    Obtiene los permisos asignados a un rol específico
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT 
                p.id,
                p.name,
                p.name as display_name,
                COALESCE(p.description, p.name) as description
            FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = %s
            ORDER BY p.name
            """, (role_id,))
            
            permisos = cursor.fetchall()
            logger.info(f"Rol {role_id} tiene {len(permisos)} permisos asignados")
            return permisos
            
    except Exception as e:
        logger.error(f"Error al obtener permisos del rol {role_id}: {e}")
        return []
    finally:
        if conn:
            conn.close()

def crear_rol(nombre, nombre_mostrar, descripcion, usuario_id=None):
    """
    Crea un nuevo rol en el sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar si ya existe un rol con ese nombre
            cursor.execute("SELECT id FROM roles WHERE name = %s", (nombre,))
            if cursor.fetchone():
                logger.warning(f"Ya existe un rol con el nombre: {nombre}")
                return None
            
            # Crear el nuevo rol - INCLUIR display_name
            cursor.execute("""
            INSERT INTO roles (name, display_name, description, created_at)
            VALUES (%s, %s, %s, NOW())
            RETURNING id, name, display_name, description, created_at
            """, (nombre, nombre_mostrar, descripcion))
            
            nuevo_rol = cursor.fetchone()
            conn.commit()
            
            # Registrar actividad
            if usuario_id:
                from controladores.controlador_usuario import registrar_actividad_usuario
                registrar_actividad_usuario(
                    usuario_id,
                    'crear_rol',
                    f'Rol "{nombre}" creado',
                    None
                )
            
            logger.info(f"Rol creado exitosamente: {nombre}")
            return nuevo_rol
            
    except Exception as e:
        logger.error(f"Error al crear rol: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def actualizar_rol(role_id, datos, usuario_id=None):
    """
    Actualiza un rol existente
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el rol existe
            cursor.execute("SELECT name FROM roles WHERE id = %s", (role_id,))
            rol_actual = cursor.fetchone()
            if not rol_actual:
                logger.warning(f"No se encontró el rol con ID: {role_id}")
                return False
            
            # Actualizar el rol - INCLUIR display_name
            cursor.execute("""
            UPDATE roles 
            SET name = %s, display_name = %s, description = %s
            WHERE id = %s
            """, (
                datos.get('name'),
                datos.get('display_name', datos.get('name')),  # usar name si no hay display_name
                datos.get('description'),
                role_id
            ))
            
            updated = cursor.rowcount > 0
            
            if updated:
                conn.commit()
                
                # Registrar actividad
                if usuario_id:
                    from controladores.controlador_usuario import registrar_actividad_usuario
                    registrar_actividad_usuario(
                        usuario_id,
                        'actualizar_rol',
                        f'Rol ID {role_id} actualizado',
                        None
                    )
                
                logger.info(f"Rol actualizado exitosamente: ID {role_id}")
            
            return updated
            
    except Exception as e:
        logger.error(f"Error al actualizar rol: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()
def eliminar_rol(role_id, usuario_id=None):
    """
    Elimina un rol del sistema (solo si no tiene usuarios asignados)
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar si el rol tiene usuarios asignados
            cursor.execute("SELECT COUNT(*) FROM users WHERE role_id = %s", (role_id,))
            user_count = cursor.fetchone()[0]
            
            if user_count > 0:
                logger.warning(f"No se puede eliminar el rol ID {role_id}: tiene {user_count} usuarios asignados")
                return False
            
            # Obtener nombre del rol para el log
            cursor.execute("SELECT name FROM roles WHERE id = %s", (role_id,))
            rol = cursor.fetchone()
            if not rol:
                logger.warning(f"No se encontró el rol con ID: {role_id}")
                return False
            
            nombre_rol = rol[0]
            
            # Eliminar permisos del rol
            cursor.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))
            
            # Eliminar el rol
            cursor.execute("DELETE FROM roles WHERE id = %s", (role_id,))
            
            deleted = cursor.rowcount > 0
            
            if deleted:
                conn.commit()
                
                # Registrar actividad
                if usuario_id:
                    from controladores.controlador_usuario import registrar_actividad_usuario
                    registrar_actividad_usuario(
                        usuario_id,
                        'eliminar_rol',
                        f'Rol "{nombre_rol}" eliminado',
                        None
                    )
                
                logger.info(f"Rol eliminado exitosamente: {nombre_rol}")
            
            return deleted
            
    except Exception as e:
        logger.error(f"Error al eliminar rol: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def asignar_permisos_rol(role_id, permission_ids, usuario_id=None):
    """
    Asigna permisos a un rol (reemplaza los permisos existentes)
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Eliminar permisos existentes del rol
            cursor.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))
            
            # Asignar nuevos permisos
            if permission_ids:
                for permission_id in permission_ids:
                    cursor.execute("""
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (%s, %s)
                    """, (role_id, permission_id))
            
            conn.commit()
            
            # Registrar actividad
            if usuario_id:
                from controladores.controlador_usuario import registrar_actividad_usuario
                registrar_actividad_usuario(
                    usuario_id,
                    'asignar_permisos_rol',
                    f'Permisos actualizados para rol ID {role_id}',
                    None
                )
            
            logger.info(f"Permisos asignados exitosamente al rol ID {role_id}")
            return True
            
    except Exception as e:
        logger.error(f"Error al asignar permisos al rol: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def inicializar_permisos_sistema():
    """
    Inicializa los permisos básicos del sistema si no existen
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        permisos_basicos = [
            ('ver_dashboard', 'Acceso al panel principal'),
            ('ver_detecciones', 'Visualizar detecciones de seguridad'),
            ('editar_detecciones', 'Modificar estado de detecciones'),
            ('exportar_detecciones', 'Exportar datos de detecciones'),
            ('ver_clientes', 'Visualizar clientes federados'),
            ('editar_clientes', 'Modificar información de clientes'),
            ('crear_clientes', 'Crear nuevos clientes federados'),
            ('eliminar_clientes', 'Eliminar clientes del sistema'),
            ('ver_reportes', 'Acceso a reportes del sistema'),
            ('exportar_reportes', 'Exportar reportes en diferentes formatos'),
            ('administrar_usuarios', 'Gestionar usuarios del sistema'),
            ('administrar_roles', 'Gestionar roles y permisos'),
            ('configurar_sistema', 'Modificar configuración del sistema'),
            ('ver_logs_sistema', 'Acceder a logs del sistema'),
            ('usar_api', 'Acceso a la API del sistema')
        ]
        
        with conn.cursor() as cursor:
            for nombre, descripcion in permisos_basicos:
                # Verificar si el permiso ya existe
                cursor.execute("SELECT id FROM permissions WHERE name = %s", (nombre,))
                if not cursor.fetchone():
                    cursor.execute("""
                    INSERT INTO permissions (name, description)
                    VALUES (%s, %s)
                    """, (nombre, descripcion))
            
            conn.commit()
            logger.info("Permisos básicos del sistema inicializados")
            return True
            
    except Exception as e:
        logger.error(f"Error al inicializar permisos del sistema: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def verificar_permiso_usuario(user_id, permission_name):
    """
    Verifica si un usuario tiene un permiso específico
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
            INNER JOIN roles r ON u.role_id = r.id
            INNER JOIN role_permissions rp ON r.id = rp.role_id
            INNER JOIN permissions p ON rp.permission_id = p.id
            WHERE u.id = %s AND p.name = %s AND u.is_active = TRUE
            """, (user_id, permission_name))
            
            return cursor.fetchone() is not None
            
    except Exception as e:
        logger.error(f"Error al verificar permiso del usuario: {e}")
        return False
    finally:
        if conn:
            conn.close()
# Agregar esta función al final del archivo:
def actualizar_permiso(permiso_id, datos, usuario_id=None):
    """
    Actualiza un permiso existente
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el permiso existe
            cursor.execute("SELECT name FROM permissions WHERE id = %s", (permiso_id,))
            permiso_actual = cursor.fetchone()
            if not permiso_actual:
                logger.warning(f"No se encontró el permiso con ID: {permiso_id}")
                return False
            
            # Actualizar el permiso (solo name y description ya que son las columnas que tienes)
            cursor.execute("""
            UPDATE permissions 
            SET name = %s, description = %s
            WHERE id = %s
            """, (datos.get('name'), datos.get('description'), permiso_id))
            
            updated = cursor.rowcount > 0
            
            if updated:
                conn.commit()
                
                # Registrar actividad
                if usuario_id:
                    from controladores.controlador_usuario import registrar_actividad_usuario
                    registrar_actividad_usuario(
                        usuario_id,
                        'actualizar_permiso',
                        f'Permiso ID {permiso_id} actualizado',
                        None
                    )
                
                logger.info(f"Permiso actualizado exitosamente: ID {permiso_id}")
            
            return updated
            
    except Exception as e:
        logger.error(f"Error al actualizar permiso: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def crear_permiso(name, display_name, description, module, usuario_id=None):
    """
    Crear un nuevo permiso (simplificado para tu estructura)
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar si ya existe
            cursor.execute("SELECT id FROM permissions WHERE name = %s", (name,))
            if cursor.fetchone():
                logger.warning(f"Ya existe un permiso con el nombre: {name}")
                return None
            
            # Crear nuevo permiso (solo name y description)
            cursor.execute("""
            INSERT INTO permissions (name, description)
            VALUES (%s, %s)
            RETURNING id, name, description
            """, (name, description))
            
            nuevo_permiso = cursor.fetchone()
            conn.commit()
            
            # Registrar actividad
            if usuario_id:
                from controladores.controlador_usuario import registrar_actividad_usuario
                registrar_actividad_usuario(
                    usuario_id,
                    'crear_permiso',
                    f'Permiso "{name}" creado',
                    None
                )
            
            logger.info(f"Permiso creado exitosamente: {name}")
            return nuevo_permiso
            
    except Exception as e:
        logger.error(f"Error al crear permiso: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()
# Agregar esta función al final del archivo:
def eliminar_permiso(permiso_id, usuario_id=None):
    """
    Elimina un permiso del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar que el permiso existe
            cursor.execute("SELECT name FROM permissions WHERE id = %s", (permiso_id,))
            permiso_actual = cursor.fetchone()
            if not permiso_actual:
                logger.warning(f"No se encontró el permiso con ID: {permiso_id}")
                return False
            
            # Verificar si el permiso está asignado a algún rol
            cursor.execute("""
            SELECT COUNT(*) FROM role_permissions 
            WHERE permission_id = %s
            """, (permiso_id,))
            
            roles_asignados = cursor.fetchone()[0]
            if roles_asignados > 0:
                logger.warning(f"No se puede eliminar el permiso ID {permiso_id}: está asignado a {roles_asignados} rol(es)")
                return False
            
            # Eliminar el permiso
            cursor.execute("DELETE FROM permissions WHERE id = %s", (permiso_id,))
            
            deleted = cursor.rowcount > 0
            
            if deleted:
                conn.commit()
                
                # Registrar actividad
                if usuario_id:
                    from controladores.controlador_usuario import registrar_actividad_usuario
                    registrar_actividad_usuario(
                        usuario_id,
                        'eliminar_permiso',
                        f'Permiso ID {permiso_id} eliminado',
                        None
                    )
                
                logger.info(f"Permiso eliminado exitosamente: ID {permiso_id}")
            
            return deleted
            
    except Exception as e:
        logger.error(f"Error al eliminar permiso: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()