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
        
        query = """
        SELECT sl.id, sl.timestamp, sl.level, sl.module, sl.message, 
               sl.user_id, u.username, sl.ip_address, sl.details
        FROM system_logs sl
        LEFT JOIN users u ON sl.user_id = u.id
        WHERE 1=1
        """
        
        params = []
        
        # Aplicar filtros si existen
        if filtros:
            if 'level' in filtros and filtros['level']:
                query += " AND sl.level = %s"
                params.append(filtros['level'])
                
            if 'module' in filtros and filtros['module']:
                query += " AND sl.module = %s"
                params.append(filtros['module'])
                
            if 'user_id' in filtros and filtros['user_id']:
                query += " AND sl.user_id = %s"
                params.append(filtros['user_id'])
                
            if 'fecha_inicio' in filtros and filtros['fecha_inicio']:
                query += " AND sl.timestamp >= %s"
                params.append(filtros['fecha_inicio'])
                
            if 'fecha_fin' in filtros and filtros['fecha_fin']:
                query += " AND sl.timestamp <= %s"
                params.append(filtros['fecha_fin'])
                
            if 'texto' in filtros and filtros['texto']:
                query += " AND (sl.message ILIKE %s OR sl.details ILIKE %s)"
                search_term = f"%{filtros['texto']}%"
                params.extend([search_term, search_term])
        
        # Ordenar y limitar resultados
        query += " ORDER BY sl.timestamp DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
            
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
        
        with conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO system_logs 
            (timestamp, level, module, message, user_id, ip_address, details)
            VALUES (NOW(), %s, %s, %s, %s, %s, %s)
            """, (level, module, message, user_id, ip_address, details))
            
            conn.commit()
            return True
            
    except Exception as e:
        logger.error(f"Error al registrar log del sistema: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def obtener_configuracion_sistema():
    """
    Obtiene la configuración general del sistema desde el archivo de configuración
    o crea un archivo con valores predeterminados si no existe
    
    Returns:
        dict: Diccionario con la configuración del sistema
    """
    try:
        # Asegurar que el directorio existe
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        # Si el archivo no existe, crear uno con configuración predeterminada
        if not os.path.exists(CONFIG_FILE):
            config_default = {
                'federated_server_host': 'localhost',
                'federated_server_port': 8080,
                'aggregation_rounds': 10,
                'min_clients_per_round': 2,
                'confidence_threshold': 0.7,
                'model_update_interval': 3600,  # segundos
                'alert_threshold': 'medium',
                'alert_notification_emails': '',
                'retention_period': 90,  # días
                'max_clients': 100,
                'updated_at': datetime.now().isoformat(),
                'updated_by': 'system'
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_default, f, indent=4)
                
            return config_default
        
        # Leer la configuración del archivo
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"Error al obtener configuración del sistema: {e}")
        
        # Devolver configuración por defecto en caso de error
        return {
            'federated_server_host': 'localhost',
            'federated_server_port': 8080,
            'aggregation_rounds': 10,
            'min_clients_per_round': 2,
            'confidence_threshold': 0.7,
            'model_update_interval': 3600,
            'alert_threshold': 'medium',
            'alert_notification_emails': '',
            'retention_period': 90,
            'max_clients': 100,
            'error': str(e)
        }

def actualizar_configuracion_sistema(nueva_config, user_id):
    """
    Actualiza la configuración del sistema
    
    Args:
        nueva_config (dict): Nueva configuración a aplicar
        user_id (int): ID del usuario que realiza el cambio
        
    Returns:
        bool: True si se actualizó correctamente, False en caso contrario
    """
    try:
        # Obtener configuración actual
        config_actual = obtener_configuracion_sistema()
        
        # Actualizar solo los campos proporcionados
        for key, value in nueva_config.items():
            if key in config_actual:
                # Convertir valores numéricos si es necesario
                if key in ['aggregation_rounds', 'min_clients_per_round', 'model_update_interval',
                          'federated_server_port', 'confidence_threshold', 'retention_period', 'max_clients']:
                    try:
                        if value is not None and value != '':
                            config_actual[key] = int(value) if isinstance(config_actual[key], int) else float(value)
                    except (ValueError, TypeError):
                        # Si la conversión falla, mantener el valor anterior
                        logger.warning(f"No se pudo convertir el valor de {key}: {value}")
                else:
                    config_actual[key] = value
        
        # Actualizar metadatos
        config_actual['updated_at'] = datetime.now().isoformat()
        config_actual['updated_by'] = user_id
        
        # Guardar configuración actualizada
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_actual, f, indent=4)
        
        # Registrar cambio en el log del sistema
        registrar_log_sistema(
            'info',
            'system_config',
            'Configuración del sistema actualizada',
            user_id=user_id,
            details=f"Configuración actualizada: {', '.join(nueva_config.keys())}"
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Error al actualizar configuración del sistema: {e}")
        return False

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
            DELETE FROM system_logs
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
                (SELECT COUNT(*) FROM system_logs) as total_logs
            """)
            
            stats['general'] = cursor.fetchone()
            
            # Actividad por día (últimos 7 días)
            cursor.execute("""
            SELECT 
                DATE(timestamp) as fecha,
                COUNT(*) as count
            FROM system_logs
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
            FROM system_logs
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
            FROM system_logs
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
            FROM system_logs sl
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