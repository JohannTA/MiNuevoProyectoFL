import logging
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def obtener_detecciones(limite=100, offset=0, filtros=None):
    """
    Obtiene lista de detecciones con posibilidad de filtrado y paginación
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        # Construir la consulta base
        query = """
        SELECT d.id, d.timestamp, d.src_ip, d.dst_ip, d.src_port, 
               d.dst_port, d.protocol, d.attack_type, d.confidence_score, 
               d.severity, d.reviewed, d.notes,
               fc.name as client_name, fc.location as client_location,
               u.username as reviewed_by_username
        FROM detections d
        LEFT JOIN federated_clients fc ON d.client_id = fc.id
        LEFT JOIN users u ON d.reviewed_by = u.id
        WHERE 1=1
        """
        
        params = []
        
        # Aplicar filtros si existen
        if filtros:
            if 'client_id' in filtros and filtros['client_id']:
                query += " AND d.client_id = %s"
                params.append(filtros['client_id'])
                
            if 'severity' in filtros and filtros['severity']:
                query += " AND d.severity = %s"
                params.append(filtros['severity'])
                
            if 'attack_type' in filtros and filtros['attack_type']:
                query += " AND d.attack_type = %s"
                params.append(filtros['attack_type'])
                
            if 'ip' in filtros and filtros['ip']:
                query += " AND (d.src_ip = %s OR d.dst_ip = %s)"
                params.extend([filtros['ip'], filtros['ip']])
                
            if 'fecha_inicio' in filtros and filtros['fecha_inicio']:
                query += " AND d.timestamp >= %s"
                params.append(filtros['fecha_inicio'])
                
            if 'fecha_fin' in filtros and filtros['fecha_fin']:
                query += " AND d.timestamp <= %s"
                params.append(filtros['fecha_fin'])
                
            if 'revisado' in filtros:
                query += " AND d.reviewed = %s"
                params.append(filtros['revisado'])
        
        # Ordenar y limitar resultados
        query += " ORDER BY d.timestamp DESC LIMIT %s OFFSET %s"
        params.extend([limite, offset])
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
            
    except Exception as e:
        logger.error(f"Error al obtener detecciones: {e}")
        return []
    finally:
        if conn:
            conn.close()

  
def obtener_total_detecciones(filtros=None):
    """
    Obtiene el número total de detecciones aplicando los filtros especificados.
    
    Args:
        filtros (dict, optional): Diccionario con los filtros a aplicar. Defaults to None.
        
    Returns:
        int: Número total de detecciones.
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return 0
        
        # Construir la consulta base
        query = "SELECT COUNT(*) FROM detections WHERE 1=1"
        params = []
        
        # Aplicar filtros si existen
        if filtros:
            if 'client_id' in filtros and filtros['client_id']:
                query += " AND client_id = %s"
                params.append(filtros['client_id'])
                
            if 'severity' in filtros and filtros['severity']:
                query += " AND severity = %s"
                params.append(filtros['severity'])
                
            if 'attack_type' in filtros and filtros['attack_type']:
                query += " AND attack_type = %s"
                params.append(filtros['attack_type'])
                
            if 'ip' in filtros and filtros['ip']:
                query += " AND (src_ip = %s OR dst_ip = %s)"
                params.extend([filtros['ip'], filtros['ip']])
                
            if 'fecha_inicio' in filtros and filtros['fecha_inicio']:
                query += " AND timestamp >= %s"
                params.append(filtros['fecha_inicio'])
                
            if 'fecha_fin' in filtros and filtros['fecha_fin']:
                query += " AND timestamp <= %s"
                params.append(filtros['fecha_fin'])
                
            if 'revisado' in filtros and filtros['revisado'] is not None:
                query += " AND reviewed = %s"
                params.append(filtros['revisado'])
        
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()[0]
            
    except Exception as e:
        logger.error(f"Error al obtener total de detecciones: {e}")
        return 0
    finally:
        if conn:
            conn.close()
def obtener_deteccion_por_id(deteccion_id):
    """
    Obtiene los detalles de una detección específica por su ID
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        query = """
        SELECT d.*, fc.name as client_name, fc.location as client_location,
               u.username as reviewed_by_username
        FROM detections d
        LEFT JOIN federated_clients fc ON d.client_id = fc.id
        LEFT JOIN users u ON d.reviewed_by = u.id
        WHERE d.id = %s
        """
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (deteccion_id,))
            return cursor.fetchone()
            
    except Exception as e:
        logger.error(f"Error al obtener detección por ID: {e}")
        return None
    finally:
        if conn:
            conn.close()

def actualizar_deteccion(deteccion_id, revisado=None, notas=None, usuario_id=None):
    """
    Actualiza el estado de una detección (revisada, notas)
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        # Construir la consulta de actualización
        update_fields = []
        params = []
        
        if revisado is not None:
            update_fields.append("reviewed = %s")
            params.append(revisado)
            
        if notas is not None:
            update_fields.append("notes = %s")
            params.append(notas)
            
        if usuario_id is not None:
            update_fields.append("reviewed_by = %s")
            params.append(usuario_id)
        
        if not update_fields:
            return True  # No hay nada que actualizar
            
        query = f"""
        UPDATE detections
        SET {", ".join(update_fields)}
        WHERE id = %s
        """
        
        params.append(deteccion_id)
        
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            updated = cursor.rowcount > 0
            conn.commit()
            return updated
            
    except Exception as e:
        logger.error(f"Error al actualizar detección: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_estadisticas_detecciones():
    """
    Obtiene estadísticas generales de las detecciones
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        stats = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Total de detecciones
            cursor.execute("SELECT COUNT(*) as total FROM detections")
            stats['total'] = cursor.fetchone()['total']
            
            # Detecciones por severidad
            cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM detections
            GROUP BY severity
            ORDER BY 
                CASE 
                    WHEN severity = 'critical' THEN 1
                    WHEN severity = 'high' THEN 2
                    WHEN severity = 'medium' THEN 3
                    WHEN severity = 'low' THEN 4
                    ELSE 5
                END
            """)
            stats['por_severidad'] = cursor.fetchall()
            
            # Detecciones por tipo de ataque (top 5)
            cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM detections
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
            """)
            stats['por_tipo'] = cursor.fetchall()
            
            # Detecciones por cliente
            cursor.execute("""
            SELECT fc.name, COUNT(*) as count
            FROM detections d
            JOIN federated_clients fc ON d.client_id = fc.id
            GROUP BY fc.name
            ORDER BY count DESC
            """)
            stats['por_cliente'] = cursor.fetchall()
            
            # Detecciones en las últimas 24 horas
            cursor.execute("""
            SELECT COUNT(*) as count
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            stats['ultimas_24h'] = cursor.fetchone()['count']
            
            # Detecciones pendientes de revisión
            cursor.execute("""
            SELECT COUNT(*) as count
            FROM detections
            WHERE reviewed = FALSE
            """)
            stats['pendientes'] = cursor.fetchone()['count']
            
            return stats
            
    except Exception as e:
        logger.error(f"Error al obtener estadísticas: {e}")
        return {}
    finally:
        if conn:
            conn.close()

def obtener_tipos_ataque():
    """
    Obtiene la lista de tipos de ataque registrados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT DISTINCT attack_type
            FROM detections
            ORDER BY attack_type
            """)
            return [row['attack_type'] for row in cursor.fetchall()]
            
    except Exception as e:
        logger.error(f"Error al obtener tipos de ataque: {e}")
        return []
    finally:
        if conn:
            conn.close()