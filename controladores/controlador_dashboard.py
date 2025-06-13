import logging
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

def obtener_datos_dashboard():
    """
    Obtiene todos los datos necesarios para el dashboard - ADAPTADO A TU BD
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.warning("No se pudo establecer conexión con la base de datos, usando datos mock")
            return obtener_datos_mock()
        
        datos = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. RESUMEN GENERAL - ADAPTADO A TU ESQUEMA
            cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM detections) as total_detecciones,
                (SELECT COUNT(*) FROM detections WHERE timestamp >= NOW() - INTERVAL '24 hours') as detecciones_24h,
                (SELECT COUNT(*) FROM detections WHERE is_confirmed IS NULL OR is_confirmed = FALSE) as pendientes_revision,
                (SELECT COUNT(*) FROM federated_clients) as total_clientes,
                (SELECT COUNT(*) FROM federated_clients WHERE status = 'active') as clientes_activos,
                (SELECT COUNT(*) FROM detections WHERE severity IN ('high', 'critical')) as alertas_criticas
            """)
            resumen = cursor.fetchone()
            datos['resumen'] = dict(resumen) if resumen else {
                'total_detecciones': 0,
                'detecciones_24h': 0,
                'pendientes_revision': 0,
                'total_clientes': 0,
                'clientes_activos': 0,
                'alertas_criticas': 0
            }
            
            # 2. DETECCIONES POR SEVERIDAD
            cursor.execute("""
            SELECT 
                COALESCE(severity, 'unknown') as severity, 
                COUNT(*) as count,
                ROUND(AVG(COALESCE(confidence_score, 0.5)), 2) as avg_confidence
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY severity
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    ELSE 5
                END
            """)
            datos['por_severidad'] = [dict(row) for row in cursor.fetchall()]
            if not datos['por_severidad']:
                datos['por_severidad'] = []
            
            # 3. DETECCIONES POR TIPO DE ATAQUE
            cursor.execute("""
            SELECT 
                COALESCE(anomaly_type, 'Desconocido') as attack_type, 
                COUNT(*) as count,
                ROUND(AVG(COALESCE(confidence_score, 0.5)), 2) as avg_confidence
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY anomaly_type
            ORDER BY count DESC
            LIMIT 6
            """)
            datos['por_tipo'] = [dict(row) for row in cursor.fetchall()]
            if not datos['por_tipo']:
                datos['por_tipo'] = []
            
            # 4. DETECCIONES RECIENTES (CORREGIDO PARA TU BD)
            cursor.execute("""
            SELECT 
                d.id, 
                d.timestamp, 
                COALESCE(d.source_ip::text, '0.0.0.0') as source_ip,
                COALESCE(d.destination_ip::text, '0.0.0.0') as destination_ip,
                COALESCE(d.anomaly_type, 'Desconocido') as attack_type, 
                COALESCE(d.severity, 'medium') as severity,
                COALESCE(d.confidence_score, 0.5) as confidence_score,
                COALESCE(fc.name, 'Cliente ' || CAST(d.client_id AS TEXT)) as client_name,
                d.is_confirmed,
                COALESCE(d.false_positive, false) as false_positive
            FROM detections d
            LEFT JOIN federated_clients fc ON d.client_id = fc.id
            ORDER BY d.timestamp DESC
            LIMIT 10
            """)
            datos['recientes'] = [dict(row) for row in cursor.fetchall()]
            if not datos['recientes']:
                datos['recientes'] = []
            
            # 5. ESTADO DE CLIENTES (CORREGIDO)
            cursor.execute("""
            SELECT 
                fc.id,
                COALESCE(fc.name, 'Cliente Sin Nombre') as name, 
                COALESCE(fc.status, 'inactive') as status,
                fc.ip_address,
                fc.last_seen,
                COALESCE(fc.model_version, 'v1.0') as model_version,
                COUNT(d.id) as total_detecciones,
                COUNT(CASE WHEN d.timestamp >= NOW() - INTERVAL '24 hours' THEN 1 END) as detecciones_24h
            FROM federated_clients fc
            LEFT JOIN detections d ON fc.id = d.client_id
            GROUP BY fc.id, fc.name, fc.status, fc.ip_address, fc.last_seen, fc.model_version
            ORDER BY 
                CASE WHEN fc.status = 'active' THEN 0 ELSE 1 END,
                fc.name NULLS LAST
            """)
            datos['clientes'] = [dict(row) for row in cursor.fetchall()]
            if not datos['clientes']:
                datos['clientes'] = []
            
            # 6. TENDENCIA DIARIA
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
            datos['tendencia'] = []
            for row in cursor.fetchall():
                trend = dict(row)
                if trend['fecha']:
                    trend['fecha'] = trend['fecha'].isoformat()
                datos['tendencia'].append(trend)
            
            # 7. ACTIVIDAD POR HORA
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
            datos['por_hora'] = [dict(row) for row in cursor.fetchall()]
            
            # 8. DETECCIONES POR CLIENTE
            cursor.execute("""
            SELECT 
                COALESCE(fc.name, 'Cliente ' || CAST(d.client_id AS TEXT)) as client_name, 
                COUNT(*) as count,
                COALESCE(fc.status, 'unknown') as status,
                MAX(d.timestamp) as ultima_deteccion
            FROM detections d
            LEFT JOIN federated_clients fc ON d.client_id = fc.id
            WHERE d.timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY fc.name, fc.status, d.client_id
            ORDER BY count DESC
            LIMIT 5
            """)
            datos['por_cliente'] = [dict(row) for row in cursor.fetchall()]
            if not datos['por_cliente']:
                datos['por_cliente'] = []
            
            # 9. ESTADÍSTICAS ADICIONALES
            cursor.execute("""
            SELECT 
                COUNT(DISTINCT source_ip) as ips_origen_unicas,
                COUNT(DISTINCT destination_ip) as ips_destino_unicas,
                COUNT(DISTINCT anomaly_type) as tipos_ataque_detectados,
                ROUND(AVG(COALESCE(confidence_score, 0.5)), 2) as confianza_promedio
            FROM detections
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            stats_adicionales = cursor.fetchone()
            datos['estadisticas_adicionales'] = dict(stats_adicionales) if stats_adicionales else {
                'ips_origen_unicas': 0,
                'ips_destino_unicas': 0,
                'tipos_ataque_detectados': 0,
                'confianza_promedio': 0.0
            }
            
        conn.close()
        
        logger.info("Datos del dashboard obtenidos exitosamente desde BD")
        return datos
        
    except Exception as e:
        logger.error(f"Error al obtener datos para dashboard: {e}")
        return obtener_datos_mock()
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def obtener_datos_mock():
    """Datos mock COMPLETOS con estructura correcta"""
    now = datetime.now()
    
    return {
        'resumen': {
            'total_detecciones': 2453,
            'detecciones_24h': 64,
            'pendientes_revision': 23,
            'total_clientes': 3,
            'clientes_activos': 2,
            'alertas_criticas': 12
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
                'id': 1, 
                'timestamp': now - timedelta(minutes=5),
                'source_ip': '192.168.1.45', 
                'destination_ip': '10.0.0.5',
                'attack_type': 'Port Scan', 
                'severity': 'medium',
                'confidence_score': 0.85, 
                'client_name': 'Cliente Norte',
                'is_confirmed': None, 
                'false_positive': False
            },
            {
                'id': 2, 
                'timestamp': now - timedelta(minutes=12),
                'source_ip': '10.0.0.100', 
                'destination_ip': '192.168.1.1',
                'attack_type': 'Brute Force', 
                'severity': 'high',
                'confidence_score': 0.92, 
                'client_name': 'Cliente Sur',
                'is_confirmed': None, 
                'false_positive': False
            },
            {
                'id': 3, 
                'timestamp': now - timedelta(minutes=20),
                'source_ip': '192.168.1.15', 
                'destination_ip': '10.0.0.10',
                'attack_type': 'SQL Injection', 
                'severity': 'critical',
                'confidence_score': 0.96, 
                'client_name': 'Cliente Este',
                'is_confirmed': None, 
                'false_positive': False
            }
        ],
        'clientes': [
            {
                'id': 1, 
                'name': 'Cliente Norte', 
                'status': 'active',
                'ip_address': '192.168.1.100', 
                'last_seen': now - timedelta(minutes=2),
                'model_version': 'v3.2', 
                'total_detecciones': 234, 
                'detecciones_24h': 12
            },
            {
                'id': 2, 
                'name': 'Cliente Sur', 
                'status': 'active',
                'ip_address': '192.168.1.101', 
                'last_seen': now - timedelta(minutes=5),
                'model_version': 'v3.1', 
                'total_detecciones': 156, 
                'detecciones_24h': 8
            },
            {
                'id': 3, 
                'name': 'Cliente Este', 
                'status': 'inactive',
                'ip_address': '192.168.1.102', 
                'last_seen': now - timedelta(hours=2),
                'model_version': 'v2.9', 
                'total_detecciones': 89, 
                'detecciones_24h': 0
            }
        ],
        'por_hora': [
            {'hora': i, 'total': max(0, 10 - abs(i - 12)), 'criticas': max(0, 2 - abs(i - 14)), 'altas': max(0, 5 - abs(i - 13)), 'normales': max(0, 8 - abs(i - 11))} 
            for i in range(24)
        ],
        'tendencia': [
            {'fecha': (now - timedelta(days=i)).strftime('%Y-%m-%d'), 'total': max(20, 50 - i*5), 'criticas': max(1, 5 - i), 'altas': max(2, 10 - i*2), 'normales': max(10, 30 - i*3)} 
            for i in range(7)
        ],
        'por_cliente': [
            {'client_name': 'Cliente Norte', 'count': 45, 'status': 'active', 'ultima_deteccion': now - timedelta(minutes=5)},
            {'client_name': 'Cliente Sur', 'count': 32, 'status': 'active', 'ultima_deteccion': now - timedelta(minutes=12)},
            {'client_name': 'Cliente Este', 'count': 18, 'status': 'inactive', 'ultima_deteccion': now - timedelta(hours=2)}
        ],
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
        'total_detecciones': 1250,
        'detecciones_24h': 43,
        'pendientes_revision': 12,
        'total_clientes': 3,
        'clientes_activos': 2,
        'alertas_criticas': 8
    }

def obtener_estado_sistema():
    """Obtiene el estado actual del sistema IDS"""
    try:
        conn = obtener_conexion()
        if not conn:
            return obtener_estado_mock()
        
        estado = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Estado de clientes federados
            cursor.execute("""
                SELECT 
                    id as client_id,
                    COALESCE(name, 'Cliente Sin Nombre') as name,
                    COALESCE(status, 'inactive') as status,
                    last_seen,
                    CASE 
                        WHEN last_seen IS NULL THEN NULL
                        ELSE EXTRACT(EPOCH FROM (NOW() - last_seen))
                    END as seconds_since_seen
                FROM federated_clients
                ORDER BY last_seen DESC NULLS LAST
            """)
            
            clientes = []
            for row in cursor.fetchall():
                cliente = dict(row)
                cliente['is_active'] = cliente['seconds_since_seen'] < 300 if cliente['seconds_since_seen'] else False
                clientes.append(cliente)
            
            estado['clientes'] = clientes
            
            # Estadísticas de red
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_detecciones,
                    COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') as detecciones_1h,
                    COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) as alertas_criticas,
                    COUNT(DISTINCT source_ip) as ips_unicas
                FROM detections
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
            """)
            
            stats = cursor.fetchone()
            estado['estadisticas'] = dict(stats) if stats else {}
            
        conn.close()
        return estado
        
    except Exception as e:
        logger.error(f"Error obteniendo estado del sistema: {e}")
        return obtener_estado_mock()

def obtener_estado_mock():
    """Estado mock del sistema"""
    return {
        'clientes': [
            {
                'client_id': 1,
                'name': 'Cliente Demo',
                'status': 'active',
                'last_seen': datetime.now(),
                'is_active': True,
                'seconds_since_seen': 30
            }
        ],
        'estadisticas': {
            'total_detecciones': 150,
            'detecciones_1h': 5,
            'alertas_criticas': 2,
            'ips_unicas': 15
        }
    }

def obtener_metricas_rendimiento():
    """Obtiene métricas de rendimiento del sistema"""
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            return {
                'total_detecciones_mes': 0,
                'promedio_diario': 0.0,
                'ultima_deteccion': None,
                'primera_deteccion': None,
                'tiempo_respuesta_promedio': 0.0,
                'cpu_uso': 0.0,
                'memoria_uso': 0.0
            }
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
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
            result = dict(metricas) if metricas else {}
            
            # Agregar métricas adicionales de sistema
            try:
                import psutil
                result['cpu_uso'] = psutil.cpu_percent()
                result['memoria_uso'] = psutil.virtual_memory().percent
            except:
                result['cpu_uso'] = 0.0
                result['memoria_uso'] = 0.0
            
            result['tiempo_respuesta_promedio'] = 0.5  # Mock value
            
            return result
            
    except Exception as e:
        logger.error(f"Error al obtener métricas de rendimiento: {e}")
        return {
            'total_detecciones_mes': 0,
            'promedio_diario': 0.0,
            'ultima_deteccion': None,
            'primera_deteccion': None,
            'tiempo_respuesta_promedio': 0.0,
            'cpu_uso': 0.0,
            'memoria_uso': 0.0
        }
    finally:
        if conn:
            conn.close()