import logging
from datetime import datetime, timedelta
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
            return obtener_datos_mock()  # Fallback a datos mock
        
        datos = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Resumen general
            cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM detections) as total_detecciones,
                (SELECT COUNT(*) FROM detections WHERE timestamp >= NOW() - INTERVAL '24 hours') as detecciones_24h,
                (SELECT COUNT(*) FROM detections WHERE is_confirmed IS NULL OR is_confirmed = FALSE) as pendientes_revision,
                (SELECT COUNT(*) FROM federated_clients) as total_clientes,
                (SELECT COUNT(*) FROM federated_clients WHERE status = 'active') as clientes_activos,
                (SELECT COUNT(DISTINCT severity) FROM detections WHERE severity IN ('high', 'critical')) as alertas_criticas,
                (SELECT version FROM ml_models WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1) as version_modelo
            """)
            resumen = cursor.fetchone()
            datos['resumen'] = dict(resumen) if resumen else obtener_resumen_mock()
            
            # Detecciones por severidad
            cursor.execute("""
            SELECT 
                severity, 
                COUNT(*) as count,
                ROUND(AVG(confidence_score), 2) as avg_confidence
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY severity
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                END
            """)
            datos['por_severidad'] = [dict(row) for row in cursor.fetchall()]
            
            # Detecciones por tipo de ataque (top 6)
            cursor.execute("""
            SELECT 
                anomaly_type as attack_type, 
                COUNT(*) as count,
                ROUND(AVG(confidence_score), 2) as avg_confidence
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
              AND anomaly_type IS NOT NULL
            GROUP BY anomaly_type
            ORDER BY count DESC
            LIMIT 6
            """)
            datos['por_tipo'] = [dict(row) for row in cursor.fetchall()]
            
            # Detecciones por cliente
            cursor.execute("""
            SELECT 
                COALESCE(fc.name, 'Cliente Desconocido') as client_name, 
                COUNT(*) as count,
                fc.status,
                MAX(d.timestamp) as ultima_deteccion
            FROM detections d
            LEFT JOIN federated_clients fc ON d.client_id = fc.id
            WHERE d.timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY fc.name, fc.status
            ORDER BY count DESC
            LIMIT 5
            """)
            datos['por_cliente'] = [dict(row) for row in cursor.fetchall()]
            
            # Detecciones recientes (últimas 10)
            cursor.execute("""
            SELECT 
                d.id, 
                d.timestamp, 
                d.source_ip, 
                d.destination_ip,
                d.anomaly_type as attack_type, 
                d.severity, 
                d.confidence_score,
                COALESCE(fc.name, 'Cliente Desconocido') as client_name,
                d.is_confirmed,
                d.false_positive
            FROM detections d
            LEFT JOIN federated_clients fc ON d.client_id = fc.id
            ORDER BY d.timestamp DESC
            LIMIT 10
            """)
            datos['recientes'] = [dict(row) for row in cursor.fetchall()]
            
            # Actividad por hora (últimas 24h)
            cursor.execute("""
            SELECT 
                EXTRACT(HOUR FROM timestamp) as hora,
                COUNT(*) as total,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as criticas,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as altas,
                COUNT(CASE WHEN severity IN ('medium', 'low') THEN 1 END) as normales
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY hora
            ORDER BY hora
            """)
            actividad_hora = cursor.fetchall()
            datos['por_hora'] = [dict(row) for row in actividad_hora]
            
            # Tendencia diaria (últimos 7 días)
            cursor.execute("""
            SELECT 
                DATE(timestamp) as fecha,
                COUNT(*) as total,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as criticas,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as altas,
                COUNT(CASE WHEN severity IN ('medium', 'low') THEN 1 END) as normales
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(timestamp)
            ORDER BY fecha
            """)
            tendencia = cursor.fetchall()
            datos['tendencia'] = [dict(row) for row in tendencia]
            
            # Estado de los clientes
            cursor.execute("""
            SELECT 
                fc.id,
                fc.name, 
                fc.status, 
                fc.ip_address,
                fc.last_seen,
                fc.model_version,
                fc.data_samples_count,
                COUNT(d.id) as total_detecciones,
                COUNT(CASE WHEN d.timestamp >= NOW() - INTERVAL '24 hours' THEN 1 END) as detecciones_24h
            FROM federated_clients fc
            LEFT JOIN detections d ON fc.id = d.client_id
            GROUP BY fc.id, fc.name, fc.status, fc.ip_address, fc.last_seen, fc.model_version, fc.data_samples_count
            ORDER BY 
                CASE WHEN fc.status = 'active' THEN 0 ELSE 1 END,
                fc.name
            """)
            datos['clientes'] = [dict(row) for row in cursor.fetchall()]
            
            # Estadísticas adicionales
            cursor.execute("""
            SELECT 
                COUNT(DISTINCT source_ip) as ips_origen_unicas,
                COUNT(DISTINCT destination_ip) as ips_destino_unicas,
                COUNT(DISTINCT anomaly_type) as tipos_ataque_detectados,
                ROUND(AVG(confidence_score), 2) as confianza_promedio
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            stats_adicionales = cursor.fetchone()
            datos['estadisticas_adicionales'] = dict(stats_adicionales) if stats_adicionales else {}
            
            logger.info("Datos del dashboard obtenidos exitosamente")
            return datos
            
    except Exception as e:
        logger.error(f"Error al obtener datos para dashboard: {e}")
        return obtener_datos_mock()  # Fallback en caso de error
    finally:
        if conn:
            conn.close()

def obtener_datos_mock():
    """
    Datos mock para cuando no hay conexión a BD o no hay datos
    """
    return {
        'resumen': {
            'total_detecciones': 2453,
            'detecciones_24h': 64,
            'pendientes_revision': 23,
            'total_clientes': 8,
            'clientes_activos': 7,
            'alertas_criticas': 12,
            'version_modelo': 'v3.2'
        },
        'por_severidad': [
            {'severity': 'critical', 'count': 12, 'avg_confidence': 0.95},
            {'severity': 'high', 'count': 28, 'avg_confidence': 0.87},
            {'severity': 'medium', 'count': 156, 'avg_confidence': 0.72},
            {'severity': 'low', 'count': 89, 'avg_confidence': 0.65}
        ],
        'por_tipo': [
            {'attack_type': 'Port Scan', 'count': 89, 'avg_confidence': 0.82},
            {'attack_type': 'Brute Force', 'count': 67, 'avg_confidence': 0.78},
            {'attack_type': 'SQL Injection', 'count': 45, 'avg_confidence': 0.91},
            {'attack_type': 'DDoS', 'count': 23, 'avg_confidence': 0.88},
            {'attack_type': 'Malware', 'count': 18, 'avg_confidence': 0.93},
            {'attack_type': 'XSS', 'count': 12, 'avg_confidence': 0.76}
        ],
        'recientes': [
            {
                'id': 1, 'timestamp': datetime.now() - timedelta(minutes=5),
                'source_ip': '192.168.1.45', 'destination_ip': '10.0.0.5',
                'attack_type': 'Port Scan', 'severity': 'medium',
                'confidence_score': 0.85, 'client_name': 'Cliente Norte',
                'is_confirmed': None, 'false_positive': False
            }
        ],
        'clientes': [
            {
                'id': 1, 'name': 'Cliente Norte', 'status': 'active',
                'ip_address': '192.168.1.100', 'last_seen': datetime.now() - timedelta(minutes=2),
                'model_version': 'v3.2', 'total_detecciones': 234, 'detecciones_24h': 12
            }
        ],
        'por_hora': [],
        'tendencia': [],
        'por_cliente': [],
        'estadisticas_adicionales': {
            'ips_origen_unicas': 45,
            'ips_destino_unicas': 23,
            'tipos_ataque_detectados': 8,
            'confianza_promedio': 0.82
        }
    }

def obtener_resumen_mock():
    """Resumen mock básico"""
    return {
        'total_detecciones': 0,
        'detecciones_24h': 0,
        'pendientes_revision': 0,
        'total_clientes': 0,
        'clientes_activos': 0,
        'alertas_criticas': 0,
        'version_modelo': 'v1.0'
    }

def obtener_metricas_rendimiento():
    """
    Obtiene métricas de rendimiento del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Métricas de rendimiento
            cursor.execute("""
            SELECT 
                COUNT(*) as total_detecciones_mes,
                ROUND(COUNT(*) / 30.0, 2) as promedio_diario,
                MAX(timestamp) as ultima_deteccion,
                MIN(timestamp) as primera_deteccion
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            """)
            
            metricas = cursor.fetchone()
            return dict(metricas) if metricas else {}
            
    except Exception as e:
        logger.error(f"Error al obtener métricas de rendimiento: {e}")
        return {}
    finally:
        if conn:
            conn.close()