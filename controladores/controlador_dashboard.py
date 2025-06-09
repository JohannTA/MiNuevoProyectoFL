import logging
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def obtener_datos_dashboard():
    """
    Obtiene todos los datos necesarios para el dashboard
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        datos = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Resumen general
            cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM detections) as total_detecciones,
                (SELECT COUNT(*) FROM detections WHERE timestamp >= NOW() - INTERVAL '24 hours') as detecciones_24h,
                (SELECT COUNT(*) FROM detections WHERE reviewed = FALSE) as pendientes_revision,
                (SELECT COUNT(*) FROM federated_clients) as total_clientes,
                (SELECT COUNT(*) FROM federated_clients WHERE status = 'connected') as clientes_conectados
            """)
            datos['resumen'] = cursor.fetchone()
            
            # Detecciones por severidad
            cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM detections
            GROUP BY severity
            """)
            datos['por_severidad'] = cursor.fetchall()
            
            # Detecciones por tipo de ataque (top 5)
            cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM detections
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
            """)
            datos['por_tipo'] = cursor.fetchall()
            
            # Detecciones por cliente
            cursor.execute("""
            SELECT fc.name, COUNT(*) as count
            FROM detections d
            JOIN federated_clients fc ON d.client_id = fc.id
            GROUP BY fc.name
            ORDER BY count DESC
            LIMIT 5
            """)
            datos['por_cliente'] = cursor.fetchall()
            
            # Detecciones recientes
            cursor.execute("""
            SELECT 
                d.id, d.timestamp, d.src_ip, d.dst_ip,
                d.attack_type, d.severity, d.confidence_score,
                fc.name as client_name
            FROM detections d
            JOIN federated_clients fc ON d.client_id = fc.id
            ORDER BY d.timestamp DESC
            LIMIT 10
            """)
            datos['recientes'] = cursor.fetchall()
            
            # Actividad por hora (últimas 24h)
            cursor.execute("""
            SELECT 
                EXTRACT(HOUR FROM timestamp) as hora,
                COUNT(*) as count
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY hora
            ORDER BY hora
            """)
            datos['por_hora'] = cursor.fetchall()
            
            # Tendencia diaria (últimos 7 días)
            cursor.execute("""
            SELECT 
                DATE(timestamp) as fecha,
                COUNT(*) as count
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY fecha
            ORDER BY fecha
            """)
            datos['tendencia'] = cursor.fetchall()
            
            # Estado de los clientes
            cursor.execute("""
            SELECT 
                fc.name, fc.status, fc.ip_address,
                fc.connected_at, fc.last_heartbeat,
                fc.model_version
            FROM federated_clients fc
            ORDER BY 
                CASE WHEN fc.status = 'connected' THEN 0 ELSE 1 END,
                fc.name
            """)
            datos['clientes'] = cursor.fetchall()
            
            return datos
            
    except Exception as e:
        logger.error(f"Error al obtener datos para dashboard: {e}")
        return {}
    finally:
        if conn:
            conn.close()