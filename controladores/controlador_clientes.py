import logging
import uuid
import hashlib
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def obtener_clientes(solo_activos=False):
    """
    Obtiene la lista de clientes federados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        query = """
        SELECT * FROM federated_clients
        """
        
        if solo_activos:
            query += " WHERE status = 'connected'"
            
        query += " ORDER BY name"
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query)
            return cursor.fetchall()
            
    except Exception as e:
        logger.error(f"Error al obtener clientes: {e}")
        return []
    finally:
        if conn:
            conn.close()

def obtener_cliente_por_id(cliente_id):
    """
    Obtiene los datos de un cliente específico por ID
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT * FROM federated_clients
            WHERE id = %s
            """, (cliente_id,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener cliente por ID: {e}")
        return None
    finally:
        if conn:
            conn.close()

def crear_cliente(nombre, ubicacion=None):
    """
    Crea un nuevo cliente federado
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        # Generar clave API única
        api_key = hashlib.sha256(f"{uuid.uuid4()}".encode('utf-8')).hexdigest()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar si ya existe un cliente con ese nombre
            cursor.execute("""
            SELECT 1 FROM federated_clients WHERE name = %s
            """, (nombre,))
            
            if cursor.fetchone():
                logger.warning(f"Ya existe un cliente con el nombre {nombre}")
                return None
            
            cursor.execute("""
            INSERT INTO federated_clients (name, location, api_key, status)
            VALUES (%s, %s, %s, 'disconnected')
            RETURNING id
            """, (nombre, ubicacion, api_key))
            
            cliente_id = cursor.fetchone()['id']
            conn.commit()
            
            # Obtener el cliente completo
            cursor.execute("""
            SELECT * FROM federated_clients
            WHERE id = %s
            """, (cliente_id,))
            
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al crear cliente: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def actualizar_cliente(cliente_id, datos):
    """
    Actualiza los datos de un cliente
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        # Campos permitidos para actualizar
        campos_permitidos = ['name', 'location', 'status', 'ip_address', 'model_version']
        
        # Construir consulta dinámica
        campos_actualizar = []
        valores = []
        
        for campo, valor in datos.items():
            if campo in campos_permitidos and valor is not None:
                campos_actualizar.append(f"{campo} = %s")
                valores.append(valor)
                
        if not campos_actualizar:
            logger.warning("No se proporcionaron campos válidos para actualizar")
            return False
            
        # Añadir ID a los valores
        valores.append(cliente_id)
        
        with conn.cursor() as cursor:
            query = f"""
            UPDATE federated_clients
            SET {", ".join(campos_actualizar)}
            WHERE id = %s
            """
            
            cursor.execute(query, valores)
            actualizado = cursor.rowcount > 0
            conn.commit()
            
            return actualizado
            
    except Exception as e:
        logger.error(f"Error al actualizar cliente: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def regenerar_api_key(cliente_id):
    """
    Regenera la clave API de un cliente
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        # Generar nueva clave API
        api_key = hashlib.sha256(f"{uuid.uuid4()}".encode('utf-8')).hexdigest()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            UPDATE federated_clients
            SET api_key = %s
            WHERE id = %s
            RETURNING api_key
            """, (api_key, cliente_id))
            
            resultado = cursor.fetchone()
            conn.commit()
            
            if resultado:
                return resultado['api_key']
            return None
            
    except Exception as e:
        logger.error(f"Error al regenerar API key: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()

def registrar_heartbeat(cliente_id, ip_address=None):
    """
    Registra un heartbeat de un cliente y actualiza su estado
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            query = """
            UPDATE federated_clients
            SET last_heartbeat = NOW(), status = 'connected'
            """
            
            # Si se proporciona IP, actualizarla también
            params = []
            if ip_address:
                query += ", ip_address = %s"
                params.append(ip_address)
                
            query += " WHERE id = %s"
            params.append(cliente_id)
            
            cursor.execute(query, params)
            actualizado = cursor.rowcount > 0
            conn.commit()
            
            return actualizado
            
    except Exception as e:
        logger.error(f"Error al registrar heartbeat: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_estadisticas_clientes():
    """
    Obtiene estadísticas generales de los clientes federados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        stats = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Total de clientes
            cursor.execute("SELECT COUNT(*) as total FROM federated_clients")
            stats['total'] = cursor.fetchone()['total']
            
            # Clientes por estado
            cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM federated_clients
            GROUP BY status
            """)
            stats['por_estado'] = cursor.fetchall()
            
            # Clientes con más detecciones
            cursor.execute("""
            SELECT fc.name, COUNT(d.id) as detecciones
            FROM federated_clients fc
            LEFT JOIN detections d ON fc.id = d.client_id
            GROUP BY fc.name
            ORDER BY detecciones DESC
            LIMIT 5
            """)
            stats['por_detecciones'] = cursor.fetchall()
            
            return stats
            
    except Exception as e:
        logger.error(f"Error al obtener estadísticas de clientes: {e}")
        return {}
    finally:
        if conn:
            conn.close()

def eliminar_cliente(cliente_id):
    """
    Elimina un cliente federado
    
    Args:
        cliente_id (int): ID del cliente a eliminar
        
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
            # Primero verificar si el cliente existe
            cursor.execute("SELECT name FROM federated_clients WHERE id = %s", (cliente_id,))
            cliente = cursor.fetchone()
            
            if not cliente:
                logger.warning(f"No se encontró el cliente con ID {cliente_id}")
                return False
            
            # Eliminar el cliente
            cursor.execute("DELETE FROM federated_clients WHERE id = %s", (cliente_id,))
            eliminado = cursor.rowcount > 0
            
            if eliminado:
                # También podríamos eliminar registros relacionados si es necesario
                # Por ejemplo: cursor.execute("DELETE FROM detections WHERE client_id = %s", (cliente_id,))
                
                conn.commit()
                logger.info(f"Cliente ID {cliente_id} eliminado correctamente")
            
            return eliminado
            
    except Exception as e:
        logger.error(f"Error al eliminar cliente: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()