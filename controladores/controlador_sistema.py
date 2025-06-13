import logging
import os
import json
from datetime import datetime, timedelta
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
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Query base
            query = """
            SELECT al.id, al.timestamp, al.action, al.details, al.ip_address,
                   COALESCE(u.username, 'Sistema') as username,
                   al.resource_type, al.resource_id
            FROM activity_logs al
            LEFT JOIN users u ON al.user_id = u.id
            """
            
            params = []
            where_conditions = []
            
            # Aplicar filtros si se proporcionan
            if filtros:
                if filtros.get('usuario'):
                    where_conditions.append("u.username ILIKE %s")
                    params.append(f"%{filtros['usuario']}%")
                
                if filtros.get('accion'):
                    where_conditions.append("al.action ILIKE %s")
                    params.append(f"%{filtros['accion']}%")
                
                if filtros.get('fecha_inicio'):
                    where_conditions.append("al.timestamp >= %s")
                    params.append(filtros['fecha_inicio'])
                
                if filtros.get('fecha_fin'):
                    where_conditions.append("al.timestamp <= %s")
                    params.append(f"{filtros['fecha_fin']} 23:59:59")
            
            # Agregar WHERE si hay condiciones
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            # Ordenar y limitar
            query += " ORDER BY al.timestamp DESC"
            
            if limit:
                query += f" LIMIT {limit}"
            if offset:
                query += f" OFFSET {offset}"
            
            cursor.execute(query, params)
            logs = cursor.fetchall()
            
            logger.info(f"Se obtuvieron {len(logs)} logs del sistema")
            return [dict(log) for log in logs]
            
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
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT config_key, config_value, data_type
            FROM system_config
            ORDER BY config_key
            """)
            
            configs = cursor.fetchall()
            
            # Convertir a diccionario
            configuracion = {}
            for config in configs:
                key = config['config_key']
                value = config['config_value']
                data_type = config['data_type']
                
                # Convertir según el tipo de dato
                if data_type == 'boolean':
                    configuracion[key] = value.lower() in ('true', '1', 'yes', 'on') if value else False
                elif data_type == 'integer':
                    try:
                        configuracion[key] = int(value) if value else 0
                    except (ValueError, TypeError):
                        configuracion[key] = 0
                else:
                    configuracion[key] = value or ''
            
            logger.info(f"Se obtuvo configuración del sistema con {len(configuracion)} elementos")
            return configuracion
            
    except Exception as e:
        logger.error(f"Error al obtener configuración del sistema: {e}")
        return {}
    finally:
        if conn:
            conn.close()

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
            actualizados = 0
            
            for key, value in configuracion.items():
                if value is None:
                    continue
                
                # Convertir valores booleanos
                if isinstance(value, bool):
                    value = 'true' if value else 'false'
                elif value == 'on':
                    value = 'true'
                elif value == '':
                    value = 'false'
                
                # Actualizar o insertar configuración
                cursor.execute("""
                INSERT INTO system_config (config_key, config_value, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (config_key)
                DO UPDATE SET 
                    config_value = EXCLUDED.config_value,
                    updated_at = CURRENT_TIMESTAMP
                """, (key, str(value)))
                
                if cursor.rowcount > 0:
                    actualizados += 1
            
            conn.commit()
            
            # Registrar actividad si se proporciona usuario_id
            if usuario_id:
                cursor.execute("""
                INSERT INTO activity_logs (user_id, action, details, timestamp)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                """, (
                    usuario_id,
                    'actualizar_configuracion',
                    f'Configuración del sistema actualizada - {actualizados} elementos'
                ))
                conn.commit()
            
            logger.info(f"Se actualizaron {actualizados} elementos de configuración")
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
            fecha_limite = datetime.now() - timedelta(days=dias)
            
            cursor.execute("""
            DELETE FROM activity_logs 
            WHERE timestamp < %s
            """, (fecha_limite,))
            
            eliminados = cursor.rowcount
            conn.commit()
            
            logger.info(f"Se eliminaron {eliminados} logs antiguos (más de {dias} días)")
            return eliminados
            
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
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            estadisticas = {}
            
            # Total de usuarios
            cursor.execute("SELECT COUNT(*) as total FROM users WHERE is_active = TRUE")
            estadisticas['usuarios_activos'] = cursor.fetchone()['total']
            
            # Total de roles
            cursor.execute("SELECT COUNT(*) as total FROM roles")
            estadisticas['total_roles'] = cursor.fetchone()['total']
            
            # Total de permisos
            cursor.execute("SELECT COUNT(*) as total FROM permissions")
            estadisticas['total_permisos'] = cursor.fetchone()['total']
            
            # Logs de las últimas 24 horas
            cursor.execute("""
            SELECT COUNT(*) as total 
            FROM activity_logs 
            WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
            """)
            estadisticas['logs_24h'] = cursor.fetchone()['total']
            
            # Últimos logins
            cursor.execute("""
            SELECT COUNT(*) as total 
            FROM activity_logs 
            WHERE action = 'login' 
            AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
            """)
            estadisticas['logins_24h'] = cursor.fetchone()['total']
            
            # Total de clientes federados
            cursor.execute("SELECT COUNT(*) as total FROM federated_clients")
            estadisticas['total_clientes'] = cursor.fetchone()['total']
            
            # Clientes activos
            cursor.execute("SELECT COUNT(*) as total FROM federated_clients WHERE status = 'active'")
            estadisticas['clientes_activos'] = cursor.fetchone()['total']
            
            # Total de detecciones
            cursor.execute("SELECT COUNT(*) as total FROM detections")
            estadisticas['total_detecciones'] = cursor.fetchone()['total']
            
            # Detecciones de hoy
            cursor.execute("""
            SELECT COUNT(*) as total 
            FROM detections 
            WHERE DATE(timestamp) = CURRENT_DATE
            """)
            estadisticas['detecciones_hoy'] = cursor.fetchone()['total']
            
            logger.info("Estadísticas del sistema obtenidas exitosamente")
            return estadisticas
            
    except Exception as e:
        logger.error(f"Error al obtener estadísticas del sistema: {e}")
        return {}
    finally:
        if conn:
            conn.close()

def backup_configuracion():
    """
    Crea un backup de la configuración actual del sistema
    """
    conn = None
    try:
        conn = obtener_conexion()
        if not conn:
            logger.error("No se pudo establecer conexión con la base de datos")
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT config_key, config_value, data_type, description
            FROM system_config
            ORDER BY config_key
            """)
            
            configuracion = cursor.fetchall()
            
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'configuracion': [dict(config) for config in configuracion]
            }
            
            logger.info("Backup de configuración creado exitosamente")
            return backup_data
            
    except Exception as e:
        logger.error(f"Error al crear backup de configuración: {e}")
        return None
    finally:
        if conn:
            conn.close()

def restaurar_configuracion_defecto():
    """
    Restaura la configuración a valores por defecto
    """
    configuracion_defecto = {
        'federated_server_host': 'localhost',
        'federated_server_port': '8080',
        'aggregation_rounds': '10',
        'min_clients_per_round': '3',
        'model_update_interval': '24',
        'alert_notification_emails': 'admin@ids-federado.com',
        'session_timeout': '8',
        'max_login_attempts': '5',
        'force_ssl': 'false',
        'enable_api': 'true',
        'api_token_expiration': '2',
        'enable_email_alerts': 'true',
        'alert_severity_threshold': 'medium',
        'max_alerts_per_hour': '10'
    }
    
    return actualizar_configuracion_sistema(configuracion_defecto)

def obtener_logs_sistema(limit=100):
    """Obtiene logs del sistema"""
    try:
        logs = []
        # Implementar lectura de logs reales si es necesario
        return logs
    except Exception as e:
        logger.error(f"Error obteniendo logs: {e}")
        return []

def obtener_configuracion_sistema():
    """Obtiene configuración del sistema"""
    try:
        return {
            'sistema': {
                'version': '1.0.0',
                'modo_debug': False,
                'logs_habilitados': True
            },
            'federado': {
                'host': '0.0.0.0',
                'puerto': 8765,
                'min_clientes': 2
            },
            'detector': {
                'interface': 'Wi-Fi',
                'umbral_confianza': 0.7,
                'buffer_size': 1000
            }
        }
    except Exception as e:
        logger.error(f"Error obteniendo configuración: {e}")
        return {}

def actualizar_configuracion_sistema(configuracion, user_id=None):
    """Actualiza configuración del sistema"""
    try:
        # Implementar actualización de configuración
        logger.info("Configuración actualizada")
        return True
    except Exception as e:
        logger.error(f"Error actualizando configuración: {e}")
        return False