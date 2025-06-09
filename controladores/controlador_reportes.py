import logging
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def generar_reporte_detecciones(filtros=None):
    """
    Genera un reporte de detecciones según los filtros especificados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {'data': [], 'stats': {}}
        
        # Construir consulta
        query_base = """
        FROM detections d
        LEFT JOIN federated_clients fc ON d.client_id = fc.id
        WHERE 1=1
        """
        
        params = []
        
        # Aplicar filtros
        if filtros:
            if 'fecha_inicio' in filtros and filtros['fecha_inicio']:
                query_base += " AND d.timestamp >= %s"
                params.append(filtros['fecha_inicio'])
                
            if 'fecha_fin' in filtros and filtros['fecha_fin']:
                query_base += " AND d.timestamp <= %s"
                params.append(filtros['fecha_fin'])
                
            if 'cliente_id' in filtros and filtros['cliente_id']:
                query_base += " AND d.client_id = %s"
                params.append(filtros['cliente_id'])
                
            if 'severidad' in filtros and filtros['severidad']:
                query_base += " AND d.severity = %s"
                params.append(filtros['severidad'])
                
            if 'tipo_ataque' in filtros and filtros['tipo_ataque']:
                query_base += " AND d.attack_type = %s"
                params.append(filtros['tipo_ataque'])
        
        # Ejecutar consultas
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Obtener datos detallados
            data_query = f"""
            SELECT d.id, d.timestamp, d.src_ip, d.dst_ip, d.protocol, 
                   d.attack_type, d.severity, d.confidence_score,
                   fc.name as client_name, fc.location as client_location
            {query_base}
            ORDER BY d.timestamp DESC
            """
            
            cursor.execute(data_query, params)
            data = cursor.fetchall()
            
            # Obtener estadísticas
            stats = {}
            
            # Total de detecciones
            cursor.execute(f"SELECT COUNT(*) as total {query_base}", params)
            stats['total'] = cursor.fetchone()['total']
            
            # Detecciones por severidad
            cursor.execute(f"""
            SELECT d.severity, COUNT(*) as count
            {query_base}
            GROUP BY d.severity
            ORDER BY 
                CASE 
                    WHEN d.severity = 'critical' THEN 1
                    WHEN d.severity = 'high' THEN 2
                    WHEN d.severity = 'medium' THEN 3
                    WHEN d.severity = 'low' THEN 4
                    ELSE 5
                END
            """, params)
            stats['por_severidad'] = cursor.fetchall()
            
            # Detecciones por tipo de ataque
            cursor.execute(f"""
            SELECT d.attack_type, COUNT(*) as count
            {query_base}
            GROUP BY d.attack_type
            ORDER BY count DESC
            LIMIT 10
            """, params)
            stats['por_tipo'] = cursor.fetchall()
            
            # Detecciones por cliente
            cursor.execute(f"""
            SELECT fc.name, COUNT(*) as count
            {query_base}
            GROUP BY fc.name
            ORDER BY count DESC
            """, params)
            stats['por_cliente'] = cursor.fetchall()
            
            # Detecciones por día/hora
            cursor.execute(f"""
            SELECT 
                DATE(d.timestamp) as fecha,
                COUNT(*) as count
            {query_base}
            GROUP BY fecha
            ORDER BY fecha
            """, params)
            stats['por_fecha'] = cursor.fetchall()
            
            return {
                'data': data,
                'stats': stats
            }
            
    except Exception as e:
        logger.error(f"Error al generar reporte de detecciones: {e}")
        return {'data': [], 'stats': {}}
    finally:
        if conn:
            conn.close()

def generar_reporte_clientes(filtros=None):
    """
    Genera un reporte sobre los clientes federados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {'data': [], 'stats': {}}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Obtener datos detallados de los clientes
            cursor.execute("""
            SELECT 
                fc.id, fc.name, fc.location, fc.status, 
                fc.connected_at, fc.last_heartbeat,
                fc.model_version,
                COUNT(d.id) as total_detecciones
            FROM federated_clients fc
            LEFT JOIN detections d ON fc.id = d.client_id
            GROUP BY fc.id
            ORDER BY fc.name
            """)
            
            data = cursor.fetchall()
            
            # Estadísticas generales
            stats = {}
            
            # Total por estado
            cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM federated_clients
            GROUP BY status
            """)
            stats['por_estado'] = cursor.fetchall()
            
            # Distribución de versiones
            cursor.execute("""
            SELECT model_version, COUNT(*) as count
            FROM federated_clients
            WHERE model_version IS NOT NULL
            GROUP BY model_version
            ORDER BY model_version DESC
            """)
            stats['por_version'] = cursor.fetchall()
            
            # Clientes por ubicación
            cursor.execute("""
            SELECT location, COUNT(*) as count
            FROM federated_clients
            WHERE location IS NOT NULL
            GROUP BY location
            ORDER BY count DESC
            """)
            stats['por_ubicacion'] = cursor.fetchall()
            
            return {
                'data': data,
                'stats': stats
            }
            
    except Exception as e:
        logger.error(f"Error al generar reporte de clientes: {e}")
        return {'data': [], 'stats': {}}
    finally:
        if conn:
            conn.close()

def generar_reporte_rendimiento():
    """
    Genera un reporte sobre el rendimiento del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        reporte = {
            'periodo': {
                'dia': {},
                'semana': {},
                'mes': {}
            }
        }
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Detecciones por día (último mes)
            cursor.execute("""
            SELECT 
                DATE(timestamp) as fecha,
                COUNT(*) as detecciones
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY fecha
            ORDER BY fecha
            """)
            reporte['detecciones_diarias'] = cursor.fetchall()
            
            # Severidad promedio por cliente
            cursor.execute("""
            SELECT 
                fc.name,
                COUNT(d.id) as total_detecciones,
                SUM(CASE 
                    WHEN d.severity = 'critical' THEN 4
                    WHEN d.severity = 'high' THEN 3
                    WHEN d.severity = 'medium' THEN 2
                    WHEN d.severity = 'low' THEN 1
                    ELSE 0
                END) as sum_severity,
                AVG(CASE 
                    WHEN d.severity = 'critical' THEN 4
                    WHEN d.severity = 'high' THEN 3
                    WHEN d.severity = 'medium' THEN 2
                    WHEN d.severity = 'low' THEN 1
                    ELSE 0
                END) as avg_severity
            FROM federated_clients fc
            LEFT JOIN detections d ON fc.id = d.client_id
            GROUP BY fc.name
            HAVING COUNT(d.id) > 0
            ORDER BY avg_severity DESC
            """)
            reporte['severidad_por_cliente'] = cursor.fetchall()
            
            # Estadísticas para periodos
            for periodo, intervalo in [('dia', '24 hours'), ('semana', '7 days'), ('mes', '30 days')]:
                # Total detecciones
                cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM detections
                WHERE timestamp >= NOW() - INTERVAL '{intervalo}'
                """)
                reporte['periodo'][periodo]['total'] = cursor.fetchone()['total']
                
                # Por severidad
                cursor.execute(f"""
                SELECT severity, COUNT(*) as count
                FROM detections
                WHERE timestamp >= NOW() - INTERVAL '{intervalo}'
                GROUP BY severity
                """)
                reporte['periodo'][periodo]['por_severidad'] = cursor.fetchall()
                
                # Top tipos de ataque
                cursor.execute(f"""
                SELECT attack_type, COUNT(*) as count
                FROM detections
                WHERE timestamp >= NOW() - INTERVAL '{intervalo}'
                GROUP BY attack_type
                ORDER BY count DESC
                LIMIT 5
                """)
                reporte['periodo'][periodo]['top_ataques'] = cursor.fetchall()
            
            return reporte
            
    except Exception as e:
        logger.error(f"Error al generar reporte de rendimiento: {e}")
        return {}
    finally:
        if conn:
            conn.close()