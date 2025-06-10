import logging
import os
import json
from datetime import datetime
from psycopg2.extras import RealDictCursor
from db.db import obtener_conexion

# Configurar logging
logger = logging.getLogger(__name__)

# Ruta para el archivo de configuración del sistema
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'system_config.json')

def obtener_logs_sistema(limit=100, offset=0, filtros=None):
    """
    Obtiene los logs del sistema con opciones de filtrado y paginación
    
    Args:
        limit (int): Cantidad máxima de registros a devolver
        offset (int): Desplazamiento para paginación
        filtros (dict): Diccionario con filtros para aplicar
        
    Returns:
        list: Lista de diccionarios con los logs del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return []
        
        # Consulta base - usar user_activity como fuente de logs del sistema
        query = """
        SELECT 
            ua.id,
            ua.timestamp as fecha_hora,
            COALESCE(u.username, 'Sistema') as usuario,
            ua.action as accion,
            ua.details as detalles,
            ua.ip_address as ip
        FROM user_activity ua
        LEFT JOIN users u ON ua.user_id = u.id
        WHERE 1=1
        """
        
        params = []
        
        # Aplicar filtros si existen
        if filtros:
            if 'usuario' in filtros and filtros['usuario']:
                query += " AND u.username ILIKE %s"
                params.append(f"%{filtros['usuario']}%")
                
            if 'accion' in filtros and filtros['accion']:
                query += " AND ua.action ILIKE %s"
                params.append(f"%{filtros['accion']}%")
                
            if 'fecha_inicio' in filtros and filtros['fecha_inicio']:
                query += " AND ua.timestamp >= %s"
                params.append(filtros['fecha_inicio'])
                
            if 'fecha_fin' in filtros and filtros['fecha_fin']:
                query += " AND ua.timestamp <= %s"
                params.append(filtros['fecha_fin'])
                
            if 'ip' in filtros and filtros['ip']:
                query += " AND ua.ip_address::text ILIKE %s"
                params.append(f"%{filtros['ip']}%")
        
        # Ordenar por fecha descendente
        query += " ORDER BY ua.timestamp DESC"
        
        # Aplicar límite y offset
        if limit:
            query += " LIMIT %s"
            params.append(limit)
            
        if offset:
            query += " OFFSET %s"
            params.append(offset)
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            logs = cursor.fetchall()
            
            # Convertir a formato esperado por la plantilla
            logs_formateados = []
            for log in logs:
                logs_formateados.append({
                    'id': log['id'],
                    'timestamp': log['fecha_hora'],
                    'level': 'info',  # Nivel por defecto
                    'module': 'users',  # Módulo por defecto
                    'message': log['accion'],
                    'details': log['detalles'],
                    'user_id': None,
                    'username': log['usuario'],
                    'ip_address': log['ip']
                })
            
            return logs_formateados
            
    except Exception as e:
        logger.error(f"Error al obtener logs del sistema: {e}")
        return []
    finally:
        if conn:
            conn.close()

def registrar_log_sistema(level, module, message, user_id=None, ip_address=None, details=None):
    """
    Registra un nuevo log en el sistema
    
    Args:
        level (str): Nivel del log (info, warning, error, critical)
        module (str): Módulo o componente que genera el log
        message (str): Mensaje principal del log
        user_id (int, optional): ID del usuario relacionado con la acción
        ip_address (str, optional): Dirección IP desde donde se realizó la acción
        details (str, optional): Detalles adicionales del log
        
    Returns:
        bool: True si se registró correctamente, False en caso contrario
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        # Usar user_activity para registrar logs del sistema
        with conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO user_activity (user_id, action, details, ip_address, timestamp)
            VALUES (%s, %s, %s, %s, NOW())
            """, (user_id, f"[{level.upper()}] {module}: {message}", details, ip_address))
            
            conn.commit()
            return True
            
    except Exception as e:
        logger.error(f"Error al agregar log del sistema: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_configuracion_sistema():
    """
    Obtiene la configuración actual del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        # Intentar obtener configuración de una tabla de configuración
        # Si no existe, devolver valores por defecto
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM system_configuration LIMIT 1")
                config = cursor.fetchone()
                
                if config:
                    return dict(config)
                else:
                    return obtener_configuracion_por_defecto()
                    
        except Exception:
            # Si la tabla no existe, devolver configuración por defecto
            return obtener_configuracion_por_defecto()
            
    except Exception as e:
        logger.error(f"Error al obtener configuración del sistema: {e}")
        return obtener_configuracion_por_defecto()
    finally:
        if conn:
            conn.close()

def obtener_configuracion_por_defecto():
    """
    Devuelve la configuración por defecto del sistema
    """
    return {
        'federated_server_host': 'localhost',
        'federated_server_port': '8080',
        'aggregation_rounds': '10',
        'min_clients_per_round': '3',
        'model_update_interval': '24',
        'alert_notification_emails': 'admin@ejemplo.com',
        'session_timeout': '8',
        'max_login_attempts': '5',
        'force_ssl': False,
        'enable_api': True,
        'api_token_expiration': '2',
        'enable_email_alerts': True,
        'alert_severity_threshold': 'medium',
        'max_alerts_per_hour': '10'
    }

def actualizar_configuracion_sistema(configuracion, usuario_id=None):
    """
    Actualiza la configuración del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return False
        
        with conn.cursor() as cursor:
            # Verificar si existe la tabla de configuración
            cursor.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'system_configuration'
            )
            """)
            
            table_exists = cursor.fetchone()[0]
            
            if not table_exists:
                # Crear la tabla si no existe
                cursor.execute("""
                CREATE TABLE system_configuration (
                    id SERIAL PRIMARY KEY,
                    federated_server_host VARCHAR(255) DEFAULT 'localhost',
                    federated_server_port VARCHAR(10) DEFAULT '8080',
                    aggregation_rounds INTEGER DEFAULT 10,
                    min_clients_per_round INTEGER DEFAULT 3,
                    model_update_interval INTEGER DEFAULT 24,
                    alert_notification_emails TEXT,
                    session_timeout INTEGER DEFAULT 8,
                    max_login_attempts INTEGER DEFAULT 5,
                    force_ssl BOOLEAN DEFAULT FALSE,
                    enable_api BOOLEAN DEFAULT TRUE,
                    api_token_expiration INTEGER DEFAULT 2,
                    enable_email_alerts BOOLEAN DEFAULT TRUE,
                    alert_severity_threshold VARCHAR(20) DEFAULT 'medium',
                    max_alerts_per_hour INTEGER DEFAULT 10,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER REFERENCES users(id)
                )
                """)
                
                # Insertar configuración inicial
                cursor.execute("""
                INSERT INTO system_configuration 
                (federated_server_host, federated_server_port, aggregation_rounds, 
                 min_clients_per_round, model_update_interval, alert_notification_emails,
                 session_timeout, max_login_attempts, force_ssl, enable_api,
                 api_token_expiration, enable_email_alerts, alert_severity_threshold,
                 max_alerts_per_hour, updated_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    configuracion.get('federated_server_host', 'localhost'),
                    configuracion.get('federated_server_port', '8080'),
                    int(configuracion.get('aggregation_rounds', 10)),
                    int(configuracion.get('min_clients_per_round', 3)),
                    int(configuracion.get('model_update_interval', 24)),
                    configuracion.get('alert_notification_emails', ''),
                    int(configuracion.get('session_timeout', 8)),
                    int(configuracion.get('max_login_attempts', 5)),
                    configuracion.get('force_ssl') == 'on',
                    configuracion.get('enable_api') == 'on',
                    int(configuracion.get('api_token_expiration', 2)),
                    configuracion.get('enable_email_alerts') == 'on',
                    configuracion.get('alert_severity_threshold', 'medium'),
                    int(configuracion.get('max_alerts_per_hour', 10)),
                    usuario_id
                ))
            else:
                # Actualizar configuración existente
                cursor.execute("""
                UPDATE system_configuration SET
                    federated_server_host = %s,
                    federated_server_port = %s,
                    aggregation_rounds = %s,
                    min_clients_per_round = %s,
                    model_update_interval = %s,
                    alert_notification_emails = %s,
                    session_timeout = %s,
                    max_login_attempts = %s,
                    force_ssl = %s,
                    enable_api = %s,
                    api_token_expiration = %s,
                    enable_email_alerts = %s,
                    alert_severity_threshold = %s,
                    max_alerts_per_hour = %s,
                    updated_at = CURRENT_TIMESTAMP,
                    updated_by = %s
                WHERE id = (SELECT MIN(id) FROM system_configuration)
                """, (
                    configuracion.get('federated_server_host', 'localhost'),
                    configuracion.get('federated_server_port', '8080'),
                    int(configuracion.get('aggregation_rounds', 10)),
                    int(configuracion.get('min_clients_per_round', 3)),
                    int(configuracion.get('model_update_interval', 24)),
                    configuracion.get('alert_notification_emails', ''),
                    int(configuracion.get('session_timeout', 8)),
                    int(configuracion.get('max_login_attempts', 5)),
                    configuracion.get('force_ssl') == 'on',
                    configuracion.get('enable_api') == 'on',
                    int(configuracion.get('api_token_expiration', 2)),
                    configuracion.get('enable_email_alerts') == 'on',
                    configuracion.get('alert_severity_threshold', 'medium'),
                    int(configuracion.get('max_alerts_per_hour', 10)),
                    usuario_id
                ))
            
            conn.commit()
            
            # Registrar la actividad
            if usuario_id:
                from controladores.controlador_usuario import registrar_actividad_usuario
                registrar_actividad_usuario(
                    usuario_id,
                    'actualizar_configuracion_sistema',
                    'Configuración del sistema actualizada',
                    None
                )
            
            return True
            
    except Exception as e:
        logger.error(f"Error al actualizar configuración del sistema: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_estado_sistema():
    """
    Obtiene el estado actual del sistema, incluyendo métricas clave
    
    Returns:
        dict: Diccionario con el estado del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {
                'status': 'error',
                'message': 'No se pudo conectar a la base de datos'
            }
        
        estado = {
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
            'db_connection': 'ok',
            'metrics': {},
            'alerts': {},
            'resources': {}
        }
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Obtener estadísticas de detecciones
            cursor.execute("""
            SELECT 
                COUNT(*) as total_detections,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as detections_24h,
                COUNT(*) FILTER (WHERE reviewed = FALSE) as pending_review,
                MIN(timestamp) as oldest_detection,
                MAX(timestamp) as newest_detection
            FROM detections
            """)
            
            estado['metrics']['detections'] = cursor.fetchone()
            
            # Obtener estadísticas de clientes
            cursor.execute("""
            SELECT 
                COUNT(*) as total_clients,
                COUNT(*) FILTER (WHERE status = 'connected') as connected_clients,
                COUNT(*) FILTER (WHERE status = 'disconnected') as disconnected_clients,
                COUNT(*) FILTER (WHERE last_heartbeat >= NOW() - INTERVAL '5 minutes') as active_clients
            FROM federated_clients
            """)
            
            estado['metrics']['clients'] = cursor.fetchone()
            
            # Obtener alertas críticas pendientes
            cursor.execute("""
            SELECT COUNT(*) as count
            FROM detections
            WHERE severity = 'critical' AND reviewed = FALSE
            """)
            
            estado['alerts']['critical_pending'] = cursor.fetchone()['count']
            
            # Obtener usuarios activos
            cursor.execute("""
            SELECT COUNT(*) as count
            FROM users
            WHERE last_activity >= NOW() - INTERVAL '1 hour'
            """)
            
            estado['metrics']['active_users'] = cursor.fetchone()['count']
            
            # Verificar espacio en disco del servidor (simulado)
            estado['resources']['disk_usage'] = {
                'total': '100GB',
                'used': '45GB',
                'free': '55GB',
                'percentage': 45
            }
            
            # Verificar uso de memoria (simulado)
            estado['resources']['memory_usage'] = {
                'total': '8GB',
                'used': '3.5GB',
                'free': '4.5GB',
                'percentage': 44
            }
            
            # Verificar uso de CPU (simulado)
            estado['resources']['cpu_usage'] = {
                'cores': 4,
                'load': 25
            }
            
            return estado
            
    except Exception as e:
        logger.error(f"Error al obtener estado del sistema: {e}")
        return {
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error_message': str(e)
        }
    finally:
        if conn:
            conn.close()

def limpiar_logs_antiguos(dias=30):
    """
    Elimina logs del sistema más antiguos que el número de días especificado
    
    Args:
        dias (int): Días de retención para los logs
        
    Returns:
        int: Cantidad de logs eliminados
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return 0
        
        with conn.cursor() as cursor:
            cursor.execute("""
            DELETE FROM user_activity
            WHERE timestamp < NOW() - INTERVAL %s DAY
            """, (dias,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            # Registrar la acción
            if deleted_count > 0:
                registrar_log_sistema(
                    'info',
                    'system_maintenance',
                    f'Limpieza automática de logs del sistema',
                    details=f'Se eliminaron {deleted_count} logs antiguos de más de {dias} días'
                )
            
            return deleted_count
            
    except Exception as e:
        logger.error(f"Error al limpiar logs antiguos: {e}")
        if conn:
            conn.rollback()
        return 0
    finally:
        if conn:
            conn.close()

def obtener_estadisticas_sistema():
    """
    Obtiene estadísticas generales del sistema para monitoreo
    
    Returns:
        dict: Diccionario con diversas estadísticas del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return {}
        
        stats = {}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Estadísticas de uso
            cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM detections) as total_detections,
                (SELECT COUNT(*) FROM federated_clients) as total_clients,
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM user_activity) as total_logs
            """)
            
            stats['general'] = cursor.fetchone()
            
            # Actividad por día (últimos 7 días)
            cursor.execute("""
            SELECT 
                DATE(timestamp) as fecha,
                COUNT(*) as count
            FROM user_activity
            WHERE timestamp >= NOW() - INTERVAL '7 days'
            GROUP BY fecha
            ORDER BY fecha
            """)
            
            stats['actividad_diaria'] = cursor.fetchall()
            
            # Top módulos con más logs
            cursor.execute("""
            SELECT 
                module,
                COUNT(*) as count
            FROM user_activity
            GROUP BY module
            ORDER BY count DESC
            LIMIT 5
            """)
            
            stats['top_modulos'] = cursor.fetchall()
            
            # Distribución de logs por nivel
            cursor.execute("""
            SELECT 
                level,
                COUNT(*) as count
            FROM user_activity
            GROUP BY level
            ORDER BY 
                CASE 
                    WHEN level = 'critical' THEN 1
                    WHEN level = 'error' THEN 2
                    WHEN level = 'warning' THEN 3
                    WHEN level = 'info' THEN 4
                    ELSE 5
                END
            """)
            
            stats['niveles_log'] = cursor.fetchall()
            
            # Top usuarios más activos
            cursor.execute("""
            SELECT 
                u.username,
                COUNT(sl.id) as count
            FROM user_activity sl
            JOIN users u ON sl.user_id = u.id
            WHERE sl.user_id IS NOT NULL
            GROUP BY u.username
            ORDER BY count DESC
            LIMIT 5
            """)
            
            stats['usuarios_activos'] = cursor.fetchall()
            
            return stats
            
    except Exception as e:
        logger.error(f"Error al obtener estadísticas del sistema: {e}")
        return {}
    finally:
        if conn:
            conn.close()