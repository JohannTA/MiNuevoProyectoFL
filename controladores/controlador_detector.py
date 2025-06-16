#!/usr/bin/env python3
"""
Controlador para funcionalidades del detector integrado
Incluye: buffer, normalización, auto-creación de federated_clients, etc.
"""

import logging
import datetime
import time
import json
import uuid
import threading
from collections import deque
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor
import psycopg2

logger = logging.getLogger(__name__)

# ========================================
# FUNCIONES DE UTILIDAD
# ========================================

def verificar_severity_constraint():
    """Verifica los valores permitidos en severity"""
    try:
        conn = obtener_conexion()
        if not conn:
            return ['low', 'medium', 'high', 'critical']
        
        with conn.cursor() as cur:
            cur.execute("""
            SELECT pg_get_constraintdef(oid) as definition
            FROM pg_constraint 
            WHERE conname = 'detections_severity_check'
            """)
            
            result = cur.fetchone()
            if result:
                constraint_def = result[0]
                import re
                matches = re.findall(r"'([^']+)'", constraint_def)
                if matches:
                    return matches
            
            return ['low', 'medium', 'high', 'critical']
            
    except Exception as e:
        logger.error(f"Error verificando constraint: {e}")
        return ['low', 'medium', 'high', 'critical']
    finally:
        if conn:
            conn.close()

def normalizar_severity(severity_input):
    """Normaliza el valor de severity a uno válido"""
    if not severity_input:
        return 'medium'
    
    valores_permitidos = verificar_severity_constraint()
    severity_lower = str(severity_input).lower().strip()
    
    # Mapeo de valores comunes
    mapeo_severity = {
        'info': 'low',
        'information': 'low',
        'informational': 'low',
        'debug': 'low',
        'notice': 'low',
        'warning': 'medium',
        'warn': 'medium',
        'error': 'high',
        'err': 'high',
        'fatal': 'critical',
        'emergency': 'critical',
        'emerg': 'critical',
        'alert': 'critical',
        'panic': 'critical'
    }
    
    # Si ya es un valor válido, devolverlo
    if severity_lower in [v.lower() for v in valores_permitidos]:
        return severity_lower
    
    # Intentar mapeo
    if severity_lower in mapeo_severity:
        mapped_value = mapeo_severity[severity_lower]
        logger.info(f"Severity mapeado: '{severity_input}' -> '{mapped_value}'")
        return mapped_value
    
    # Fallback por número
    try:
        severity_num = float(severity_input)
        if severity_num <= 0.3:
            return 'low'
        elif severity_num <= 0.6:
            return 'medium'
        elif severity_num <= 0.9:
            return 'high'
        else:
            return 'critical'
    except:
        pass
    
    logger.warning(f"Severity desconocido '{severity_input}', usando 'medium'")
    return 'medium'

def verificar_tabla_existe(table_name):
    """Verifica si una tabla existe en la base de datos"""
    try:
        conn = obtener_conexion()
        if not conn:
            return False
        
        with conn.cursor() as cur:
            cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = %s
            )
            """, (table_name,))
            
            return cur.fetchone()[0]
            
    except Exception as e:
        logger.error(f"Error verificando tabla {table_name}: {e}")
        return False
    finally:
        if conn:
            conn.close()

def obtener_usuario_completo_con_dispositivo(user_id):
    """Obtiene información completa del usuario con su dispositivo desde PostgreSQL"""
    try:
        conn = obtener_conexion()
        if not conn:
            return None
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = """
            SELECT 
                u.id as user_id,
                u.username,
                u.first_name,
                u.last_name,
                u.email,
                u.is_active,
                u.allowed_computing_device_id,
                r.display_name as role_display_name,
                cd.id as device_id,
                cd.type as device_type,
                cd.brand as device_brand,
                cd.model as device_model,
                cd.serial_number as device_serial,
                cd.status as device_status
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            LEFT JOIN computing_devices cd ON u.allowed_computing_device_id = cd.id
            WHERE u.id = %s
            """
            
            cur.execute(query, (user_id,))
            result = cur.fetchone()
            
            if result:
                return {
                    "user": {
                        "id": result['user_id'],
                        "username": result['username'],
                        "first_name": result['first_name'],
                        "last_name": result['last_name'],
                        "email": result['email'],
                        "role_display_name": result['role_display_name'],
                        "is_active": result['is_active'],
                        "allowed_computing_device_id": result['allowed_computing_device_id']
                    },
                    "computing_device": {
                        "id": result['device_id'],
                        "type": result['device_type'],
                        "brand": result['device_brand'],
                        "model": result['device_model'],
                        "serial_number": result['device_serial'],
                        "status": result['device_status']
                    } if result['device_id'] else None
                }
            return None
            
    except Exception as e:
        logger.error(f"Error obteniendo usuario completo: {e}")
        return None
    finally:
        if conn:
            conn.close()

def auto_crear_federated_client(device_id, device_info):
    """Auto-crea federated_client si no existe"""
    if not verificar_tabla_existe('federated_clients'):
        logger.warning("Tabla 'federated_clients' no existe - usando device_id directamente")
        return device_id
        
    try:
        conn = obtener_conexion()
        if not conn:
            return device_id
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Verificar si ya existe
            cur.execute("""
            SELECT id, client_id, name FROM federated_clients WHERE id = %s
            """, (device_id,))
            
            existing_client = cur.fetchone()
            
            if existing_client:
                logger.info(f"Federated client existente: ID={existing_client['id']}, Name={existing_client['name']}")
                return existing_client['id']
            
            # Crear nuevo federated_client
            client_id_name = f"device_{device_id}_auto"
            name = f"{device_info.get('brand', 'Unknown')} {device_info.get('model', 'Device')} - Auto"
            description = f"Auto-created for {device_info.get('brand')} {device_info.get('model')} (#{device_info.get('serial_number')})"
            
            # Verificar columnas disponibles
            cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'federated_clients'
            ORDER BY ordinal_position
            """)
            
            available_columns = [row[0] for row in cur.fetchall()]
            
            # Construir INSERT dinámicamente
            insert_fields = ['id']
            insert_values = [device_id]
            
            if 'client_id' in available_columns:
                insert_fields.append('client_id')
                insert_values.append(client_id_name)
            
            if 'name' in available_columns:
                insert_fields.append('name')
                insert_values.append(name)
            
            if 'description' in available_columns:
                insert_fields.append('description')
                insert_values.append(description)
            
            if 'status' in available_columns:
                insert_fields.append('status')
                insert_values.append('active')
            
            if 'created_at' in available_columns:
                insert_fields.append('created_at')
                insert_values.append(datetime.datetime.now())
            
            if 'updated_at' in available_columns:
                insert_fields.append('updated_at')
                insert_values.append(datetime.datetime.now())
            
            if 'api_key' in available_columns:
                insert_fields.append('api_key')
                insert_values.append(f"api_key_device_{device_id}")
            
            placeholders = ', '.join(['%s'] * len(insert_values))
            fields_str = ', '.join(insert_fields)
            
            insert_query = f"""
            INSERT INTO federated_clients ({fields_str})
            VALUES ({placeholders})
            """
            
            cur.execute(insert_query, insert_values)
            conn.commit()
            
            logger.info(f"Federated client auto-creado: ID={device_id}, Name={name}")
            return device_id
            
    except Exception as e:
        logger.error(f"Error auto-creando federated_client: {e}")
        return device_id
    finally:
        if conn:
            conn.close()

# ========================================
# CLASE BUFFER DE DETECCIONES
# ========================================

class DetectionBuffer:
    """Buffer temporal para detecciones antes de guardar en BD"""
    
    def __init__(self, max_size=1000, flush_interval=30):
        self.buffer = deque(maxlen=max_size)
        self.buffer_lock = threading.Lock()
        self.flush_interval = flush_interval
        self.last_flush = time.time()
        self.total_buffered = 0
        self.total_saved = 0
        
        # Iniciar hilo de guardado periódico
        self.flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.flush_thread.start()
        
    def add_detection(self, detection_data):
        """Añade una detección al buffer"""
        with self.buffer_lock:
            detection_data['buffered_at'] = datetime.datetime.now()
            self.buffer.append(detection_data)
            self.total_buffered += 1
            
        # Flush si el buffer está lleno
        if len(self.buffer) >= self.buffer.maxlen * 0.8:
            self._flush_to_database()
    
    def _periodic_flush(self):
        """Hilo que hace flush periódico del buffer"""
        while True:
            try:
                time.sleep(self.flush_interval)
                current_time = time.time()
                
                if (current_time - self.last_flush >= self.flush_interval and len(self.buffer) > 0):
                    self._flush_to_database()
                    
            except Exception as e:
                logger.error(f"Error en flush periódico: {e}")
    
    def _flush_to_database(self):
        """Guarda todas las detecciones del buffer a la BD con manejo robusto"""
        if len(self.buffer) == 0:
            return
            
        with self.buffer_lock:
            detections_to_save = list(self.buffer)
            self.buffer.clear()
        
        if not detections_to_save:
            return
            
        conn = None
        try:
            conn = obtener_conexion()
            if not conn:
                with self.buffer_lock:
                    self.buffer.extendleft(reversed(detections_to_save))
                logger.warning(f"Sin conexión BD - {len(detections_to_save)} detecciones devueltas al buffer")
                return
            
            saved_count = 0
            with conn.cursor() as cursor:
                for detection in detections_to_save:
                    try:
                        # Normalizar severity antes de insertar
                        original_severity = detection.get('severity')
                        normalized_severity = normalizar_severity(original_severity)
                        
                        # Verificar/crear federated_client si hay info del dispositivo
                        client_id = detection.get('client_id', 1)
                        raw_data = detection.get('raw_data', {})
                        
                        if isinstance(raw_data, dict):
                            device_info = raw_data.get('computing_device_info', {})
                            if device_info and device_info.get('id'):
                                client_id = auto_crear_federated_client(device_info['id'], device_info)
                        
                        # Verificar model_id
                        model_id = 1
                        cursor.execute("SELECT EXISTS (SELECT 1 FROM ml_models WHERE id = %s)", (model_id,))
                        if not cursor.fetchone()[0]:
                            # Crear modelo por defecto si no existe
                            cursor.execute("""
                            INSERT INTO ml_models (id, name, version, model_type, description, is_active, created_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO NOTHING
                            """, (1, 'Default IDS Model', '1.0', 'Random Forest', 'Modelo por defecto', True, 1))
                        
                        # Insertar detección con UPSERT
                        cursor.execute("""
                            INSERT INTO detections (
                                detection_id, client_id, model_id, timestamp, source_ip, destination_ip,
                                source_port, destination_port, protocol, anomaly_type,
                                severity, confidence_score, raw_data, is_confirmed, false_positive
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (detection_id) DO UPDATE SET
                                timestamp = EXCLUDED.timestamp,
                                confidence_score = EXCLUDED.confidence_score,
                                severity = EXCLUDED.severity
                        """, (
                            detection.get('detection_id', f"det_{int(time.time()*1000)}_{saved_count}"),
                            client_id,
                            model_id,
                            detection.get('timestamp', datetime.datetime.now()),
                            detection.get('source_ip', '0.0.0.0'),
                            detection.get('destination_ip', '0.0.0.0'),
                            detection.get('source_port', 0),
                            detection.get('destination_port', 0),
                            detection.get('protocol', 'TCP'),
                            detection.get('anomaly_type', 'Unknown'),
                            normalized_severity,
                            detection.get('confidence_score', 0.5),
                            json.dumps(detection.get('raw_data', {})),
                            False,
                            False
                        ))
                        saved_count += 1
                        
                    except Exception as e:
                        logger.error(f"Error guardando detección individual: {e}")
                        continue
                
                conn.commit()
            
            self.total_saved += saved_count
            self.last_flush = time.time()
            
            logger.info(f"💾 Buffer flush: {saved_count}/{len(detections_to_save)} detecciones guardadas")
            
        except Exception as e:
            logger.error(f"Error en flush masivo a BD: {e}")
            with self.buffer_lock:
                self.buffer.extendleft(reversed(detections_to_save))
        finally:
            if conn:
                conn.close()
    
    def get_stats(self):
        """Obtiene estadísticas del buffer"""
        with self.buffer_lock:
            return {
                'buffer_size': len(self.buffer),
                'total_buffered': self.total_buffered,
                'total_saved': self.total_saved,
                'save_rate': (self.total_saved / max(self.total_buffered, 1)) * 100,
                'last_flush': datetime.datetime.fromtimestamp(self.last_flush).isoformat()
            }

# ========================================
# FUNCIONES PRINCIPALES
# ========================================

def procesar_deteccion_entrante(detection_data):
    """Procesa una detección entrante del detector_integrado"""
    try:
        # Validar datos mínimos
        required_fields = ['detection_id', 'user_id', 'client_id', 'anomaly_type']
        for field in required_fields:
            if field not in detection_data:
                return {'success': False, 'error': f'Missing field: {field}'}
        
        # Normalizar severity automáticamente
        original_severity = detection_data.get('severity')
        normalized_severity = normalizar_severity(original_severity)
        detection_data['severity'] = normalized_severity
        
        # Log de recepción
        logger.info(f"🎯 Detección recibida: {detection_data['anomaly_type']} | " +
                   f"Severity: {original_severity} -> {normalized_severity} | " +
                   f"User: {detection_data['user_id']} | " +
                   f"Confianza: {detection_data.get('confidence_score', 0):.2f}")
        
        return {
            'success': True,
            'message': 'Detección procesada exitosamente',
            'detection_id': detection_data['detection_id'],
            'severity_mapping': {
                'original': original_severity,
                'normalized': normalized_severity
            },
            'processed': True
        }
        
    except Exception as e:
        logger.error(f"Error procesando detección: {e}")
        return {'success': False, 'error': str(e)}

def obtener_mapeo_usuarios_dispositivos():
    """Obtiene el mapeo de usuarios-dispositivos-federated_clients"""
    try:
        conn = obtener_conexion()
        if not conn:
            return {"error": "Sin conexión BD"}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
            SELECT 
                u.id as user_id,
                u.username,
                u.first_name || ' ' || u.last_name as full_name,
                u.email,
                cd.id as device_id,
                cd.brand || ' ' || cd.model as device_name,
                cd.serial_number,
                cd.status as device_status,
                fc.id as federated_client_id,
                COALESCE(fc.client_id, fc.name) as federated_client_name,
                fc.status as fc_status
            FROM users u
            LEFT JOIN computing_devices cd ON u.allowed_computing_device_id = cd.id
            LEFT JOIN federated_clients fc ON cd.id = fc.id
            WHERE u.allowed_computing_device_id IS NOT NULL
            ORDER BY u.id
            """)
            
            mapping = cur.fetchall()
            
            return {
                "success": True,
                "mapping": [dict(row) for row in mapping],
                "total_users": len(mapping)
            }
            
    except Exception as e:
        logger.error(f"Error consultando mapeo: {e}")
        return {"error": f"Error consultando mapeo: {e}"}
    finally:
        if conn:
            conn.close()

def obtener_health_check_extendido():
    """Health check extendido del sistema detector"""
    try:
        # Verificar BD
        db_status = "error"
        tables_status = {}
        
        try:
            conn = obtener_conexion()
            if conn:
                db_status = "ok"
                tables_status = {
                    'users': verificar_tabla_existe('users'),
                    'computing_devices': verificar_tabla_existe('computing_devices'),
                    'federated_clients': verificar_tabla_existe('federated_clients'),
                    'detections': verificar_tabla_existe('detections'),
                    'ml_models': verificar_tabla_existe('ml_models')
                }
                conn.close()
        except Exception as e:
            logger.error(f"Error verificando BD: {e}")
        
        return {
            "status": "ok",
            "message": "Sistema detector funcionando correctamente",
            "timestamp": datetime.datetime.now().isoformat(),
            "database": {
                "connection": db_status,
                "tables": tables_status
            },
            "severity_constraint": verificar_severity_constraint()
        }
        
    except Exception as e:
        logger.error(f"Error en health check: {e}")
        return {"error": str(e)}