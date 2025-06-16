#!/usr/bin/env python3
"""
Servidor de prueba completo con integración a PostgreSQL
Mapeo correcto entre computing_devices y federated_clients
"""

from flask import Flask, jsonify, request
import logging
import sys
import os
from datetime import datetime
import json
import uuid

# Agregar el directorio db al path
sys.path.append(os.path.join(os.path.dirname(__file__), 'db'))

try:
    from db import obtener_conexion
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    # PROBAR LA CONEXIÓN REAL AL IMPORTAR
    print("🔗 Probando conexión a PostgreSQL...")
    test_conn = obtener_conexion()
    if test_conn:
        test_conn.close()
        print("✅ Conexión a PostgreSQL exitosa")
        BD_DISPONIBLE = True
    else:
        print("❌ Error de conexión a PostgreSQL")
        BD_DISPONIBLE = False
        
except ImportError as e:
    print(f"❌ Error importando módulos de BD: {e}")
    print("💡 Asegúrate de tener psycopg2 instalado: pip install psycopg2-binary")
    BD_DISPONIBLE = False
except Exception as e:
    print(f"❌ Error de conexión a BD: {e}")
    BD_DISPONIBLE = False

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def verificar_tabla_existe(table_name):
    """Verifica si una tabla existe en la base de datos"""
    if not BD_DISPONIBLE:
        return False
        
    conn = obtener_conexion()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = %s
            )
            """, (table_name,))
            
            return cur.fetchone()[0]
            
    except psycopg2.Error as e:
        print(f"❌ Error verificando tabla {table_name}: {e}")
        return False
    finally:
        conn.close()

def obtener_usuario_completo(user_id):
    """Obtiene información completa del usuario desde PostgreSQL"""
    if not BD_DISPONIBLE:
        return None
        
    conn = obtener_conexion()
    if not conn:
        return None
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Query para obtener usuario con su dispositivo asignado
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
            
    except psycopg2.Error as e:
        print(f"❌ Error en consulta de usuario: {e}")
        return None
    finally:
        conn.close()

def auto_crear_federated_client(device_id, device_info):
    """Auto-crea federated_client si no existe"""
    if not BD_DISPONIBLE:
        print("⚠️ BD no disponible para federated_client")
        return None
    
    # Verificar si la tabla federated_clients existe
    if not verificar_tabla_existe('federated_clients'):
        print("⚠️ Tabla 'federated_clients' no existe - usando device_id directamente")
        return device_id  # Fallback: usar device_id como client_id
        
    conn = obtener_conexion()
    if not conn:
        return device_id  # Fallback
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Primero verificar si ya existe un federated_client para este device
            cur.execute("""
            SELECT id, client_id, name FROM federated_clients WHERE id = %s
            """, (device_id,))
            
            existing_client = cur.fetchone()
            
            if existing_client:
                print(f"✅ Federated client existente encontrado:")
                print(f"   ID: {existing_client['id']}")
                print(f"   Client ID: {existing_client['client_id']}")
                print(f"   Name: {existing_client['name']}")
                return existing_client['id']
            
            # Crear nuevo federated_client
            client_id_name = f"device_{device_id}_auto"
            name = f"{device_info.get('brand', 'Unknown')} {device_info.get('model', 'Device')} - Auto"
            description = f"Auto-created for {device_info.get('brand')} {device_info.get('model')} (#{device_info.get('serial_number')})"
            
            # Verificar qué campos tiene la tabla federated_clients
            cur.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'federated_clients'
            ORDER BY ordinal_position
            """)
            
            columns_info = cur.fetchall()
            available_columns = [col['column_name'] for col in columns_info]
            
            print(f"📋 Columnas disponibles en federated_clients: {available_columns}")
            
            # Construir INSERT dinámicamente basado en las columnas disponibles
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
                insert_values.append(datetime.now())
            
            if 'updated_at' in available_columns:
                insert_fields.append('updated_at')
                insert_values.append(datetime.now())
            
            # Si tiene api_key, generar uno
            if 'api_key' in available_columns:
                insert_fields.append('api_key')
                insert_values.append(f"api_key_device_{device_id}")
            
            # Construir query
            placeholders = ', '.join(['%s'] * len(insert_values))
            fields_str = ', '.join(insert_fields)
            
            insert_query = f"""
            INSERT INTO federated_clients ({fields_str})
            VALUES ({placeholders})
            """
            
            print(f"🔧 Creando federated_client:")
            print(f"   ID: {device_id}")
            print(f"   Client ID: {client_id_name}")
            print(f"   Name: {name}")
            print(f"   Campos: {insert_fields}")
            
            cur.execute(insert_query, insert_values)
            conn.commit()
            
            print(f"✅ Federated client auto-creado exitosamente!")
            
            return device_id
            
    except psycopg2.Error as e:
        print(f"❌ Error auto-creando federated_client: {e}")
        print(f"🔄 Usando device_id como fallback: {device_id}")
        conn.rollback()
        return device_id  # Fallback: usar device_id directamente
    finally:
        conn.close()

def guardar_deteccion_completa(detection_data, user_info, device_info):
    """Guarda detección completa con auto-creación de federated_client"""
    if not BD_DISPONIBLE:
        print("⚠️ BD no disponible")
        return False
        
    device_id = device_info.get('id')
    
    # Auto-crear federated_client si no existe
    federated_client_id = auto_crear_federated_client(device_id, device_info)
    
    if not federated_client_id:
        print(f"❌ No se pudo crear/obtener federated_client para device {device_id}")
        return False
    
    conn = obtener_conexion()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cur:
            # Generar UUID para la detección
            detection_uuid = str(uuid.uuid4())
            
            # Preparar timestamp
            timestamp_str = detection_data.get('timestamp')
            if timestamp_str:
                try:
                    if 'T' in timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        timestamp = datetime.fromisoformat(timestamp_str)
                except:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            # Verificar estructura de la tabla detections
            cur.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns 
            WHERE table_name = 'detections'
            ORDER BY ordinal_position
            """)
            
            columns = cur.fetchall()
            column_names = [col[0] for col in columns]
            
            print(f"📋 Estructura de detections: {column_names}")
            
            # Preparar datos para insertar
            raw_data_json = json.dumps(detection_data.get('raw_data', {}), ensure_ascii=False)
            
            # Campos básicos requeridos
            insert_fields = [
                'detection_id', 'client_id', 'anomaly_type', 'severity', 
                'confidence_score', 'source_ip', 'destination_ip', 
                'timestamp', 'raw_data'
            ]
            
            insert_values = [
                detection_uuid,
                federated_client_id,
                detection_data.get('anomaly_type'),
                detection_data.get('severity'),
                float(detection_data.get('confidence_score', 0.0)),
                detection_data.get('source_ip'),
                detection_data.get('destination_ip'),
                timestamp,
                raw_data_json
            ]
            
            # Campos opcionales
            if 'source_port' in column_names:
                insert_fields.append('source_port')
                insert_values.append(int(detection_data.get('source_port', 0)))
            
            if 'destination_port' in column_names:
                insert_fields.append('destination_port')
                insert_values.append(int(detection_data.get('destination_port', 0)))
            
            if 'protocol' in column_names:
                insert_fields.append('protocol')
                insert_values.append(detection_data.get('protocol'))
            
            if 'model_id' in column_names:
                insert_fields.append('model_id')
                insert_values.append(1)  # ID del modelo por defecto
            
            if 'is_confirmed' in column_names:
                insert_fields.append('is_confirmed')
                insert_values.append(False)
            
            if 'false_positive' in column_names:
                insert_fields.append('false_positive')
                insert_values.append(False)
            
            # Construir query dinámicamente
            placeholders = ', '.join(['%s'] * len(insert_values))
            fields_str = ', '.join(insert_fields)
            
            insert_query = f"""
            INSERT INTO detections ({fields_str})
            VALUES ({placeholders})
            RETURNING id
            """
            
            print(f"🔧 Insertando detección:")
            print(f"   UUID: {detection_uuid}")
            print(f"   Client ID: {federated_client_id}")
            print(f"   Device ID: {device_id}")
            print(f"   Tipo: {detection_data.get('anomaly_type')}")
            print(f"   Severidad: {detection_data.get('severity')}")
            
            cur.execute(insert_query, insert_values)
            detection_db_id = cur.fetchone()[0]
            conn.commit()
            
            print(f"✅ Detección guardada exitosamente:")
            print(f"   DB ID: {detection_db_id}")
            print(f"   UUID: {detection_uuid}")
            
            return {
                'uuid': detection_uuid,
                'db_id': detection_db_id,
                'federated_client_id': federated_client_id,
                'device_id': device_id,
                'auto_created_client': True
            }
            
    except psycopg2.Error as e:
        print(f"❌ Error guardando detección: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>/complete-info', methods=['GET'])
def get_user_complete_info(user_id):
    """Endpoint para obtener información completa del usuario"""
    print(f"📋 Solicitud de información para usuario ID: {user_id}")
    
    if not BD_DISPONIBLE:
        return jsonify({
            "success": False,
            "error": "Base de datos no disponible"
        }), 503
    
    user_data = obtener_usuario_completo(user_id)
    
    if user_data and user_data['user']:
        if user_data['computing_device']:
            print(f"✅ Usuario encontrado: {user_data['user']['username']}")
            print(f"   💻 Dispositivo: {user_data['computing_device']['brand']} {user_data['computing_device']['model']}")
            
            response = {
                "success": True,
                **user_data
            }
            return jsonify(response)
        else:
            print(f"❌ Usuario {user_data['user']['username']} no tiene dispositivo asignado")
            return jsonify({
                "success": False,
                "error": f"Usuario no tiene dispositivo de cómputo asignado"
            }), 400
    else:
        print(f"❌ Usuario ID {user_id} no encontrado en BD")
        return jsonify({
            "success": False,
            "error": f"Usuario ID {user_id} no encontrado"
        }), 404

@app.route('/api/buffer/add-detection', methods=['POST'])
def add_detection():
    """Endpoint para recibir y guardar detecciones con auto-creación"""
    detection_data = request.get_json()
    
    print(f"🎯 DETECCIÓN RECIBIDA:")
    print(f"   ID: {detection_data.get('detection_id')}")
    print(f"   Usuario: {detection_data.get('user_id')}")
    print(f"   Cliente: {detection_data.get('client_id')}")
    print(f"   Tipo: {detection_data.get('anomaly_type')}")
    print(f"   Severidad: {detection_data.get('severity')}")
    print(f"   Confianza: {detection_data.get('confidence_score')}")
    
    # Extraer información del raw_data
    raw_data = detection_data.get('raw_data', {})
    user_info = raw_data.get('user_info', {})
    device_info = raw_data.get('computing_device_info', {})
    
    if user_info:
        print(f"   👤 Usuario: {user_info.get('full_name')} (@{user_info.get('username')})")
    
    if device_info:
        print(f"   💻 Dispositivo: {device_info.get('brand')} {device_info.get('model')}")
        print(f"   🔢 Device ID: {device_info.get('id')}")
    
    # Guardar con auto-creación de federated_client
    result = guardar_deteccion_completa(detection_data, user_info, device_info)
    
    if result:
        print(f"   ✅ Guardado en PostgreSQL exitosamente")
        print("   " + "="*50)
        
        return jsonify({
            "success": True,
            "message": "Detección guardada en PostgreSQL",
            "detection_id": detection_data.get('detection_id'),
            "database_uuid": result['uuid'],
            "database_id": result['db_id'],
            "federated_client_id": result['federated_client_id'],
            "device_id": result['device_id'],
            "auto_created_client": result.get('auto_created_client', False),
            "saved_to_database": True
        })
    else:
        print(f"   ⚠️ Error guardando en PostgreSQL")
        print("   " + "="*50)
        
        return jsonify({
            "success": True,  # Mantener success para que el detector no falle
            "message": "Detección recibida pero no guardada en BD",
            "detection_id": detection_data.get('detection_id'),
            "saved_to_database": False
        })

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de salud del servidor"""
    db_status = "ok" if BD_DISPONIBLE else "error"
    
    tables_status = {}
    if BD_DISPONIBLE:
        tables_status = {
            'users': verificar_tabla_existe('users'),
            'computing_devices': verificar_tabla_existe('computing_devices'),
            'federated_clients': verificar_tabla_existe('federated_clients'),
            'detections': verificar_tabla_existe('detections')
        }
    
    return jsonify({
        "status": "ok",
        "message": "Servidor funcionando correctamente",
        "database_connection": db_status,
        "tables": tables_status,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/mapping/info', methods=['GET'])
def mapping_info():
    """Endpoint para ver el mapeo actual de usuarios-dispositivos-federated_clients"""
    if not BD_DISPONIBLE:
        return jsonify({"error": "BD no disponible"}), 503
    
    conn = obtener_conexion()
    if not conn:
        return jsonify({"error": "Error de conexión"}), 500
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Query para ver toda la relación
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
                fc.client_id as federated_client_name,
                fc.status as fc_status
            FROM users u
            LEFT JOIN computing_devices cd ON u.allowed_computing_device_id = cd.id
            LEFT JOIN federated_clients fc ON cd.id = fc.id
            WHERE u.allowed_computing_device_id IS NOT NULL
            ORDER BY u.id
            """)
            
            mapping = cur.fetchall()
            
            return jsonify({
                "success": True,
                "mapping": [dict(row) for row in mapping],
                "total_users": len(mapping)
            })
            
    except psycopg2.Error as e:
        return jsonify({"error": f"Error consultando mapeo: {e}"}), 500
    finally:
        conn.close()

@app.route('/api/detections/recent', methods=['GET'])
def get_recent_detections():
    """Endpoint para obtener detecciones recientes"""
    if not BD_DISPONIBLE:
        return jsonify({"error": "BD no disponible"}), 503
    
    limit = request.args.get('limit', 10, type=int)
    
    conn = obtener_conexion()
    if not conn:
        return jsonify({"error": "Error de conexión"}), 500
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
            SELECT 
                d.id,
                d.detection_id,
                d.client_id,
                d.anomaly_type,
                d.severity,
                d.confidence_score,
                d.source_ip,
                d.destination_ip,
                d.timestamp,
                d.created_at,
                fc.client_id as federated_client_name
            FROM detections d
            LEFT JOIN federated_clients fc ON d.client_id = fc.id
            ORDER BY d.created_at DESC
            LIMIT %s
            """, (limit,))
            
            detections = cur.fetchall()
            
            return jsonify({
                "success": True,
                "detections": [dict(row) for row in detections],
                "total": len(detections)
            })
            
    except psycopg2.Error as e:
        return jsonify({"error": f"Error consultando detecciones: {e}"}), 500
    finally:
        conn.close()

@app.route('/api/stats/summary', methods=['GET'])
def get_stats_summary():
    """Endpoint para obtener estadísticas resumidas"""
    if not BD_DISPONIBLE:
        return jsonify({"error": "BD no disponible"}), 503
    
    conn = obtener_conexion()
    if not conn:
        return jsonify({"error": "Error de conexión"}), 500
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Estadísticas generales
            cur.execute("""
            SELECT 
                COUNT(*) as total_detections,
                COUNT(DISTINCT client_id) as active_clients,
                AVG(confidence_score) as avg_confidence,
                MAX(timestamp) as last_detection
            FROM detections
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            """)
            
            stats = cur.fetchone()
            
            # Detecciones por severidad
            cur.execute("""
            SELECT severity, COUNT(*) as count
            FROM detections
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY severity
            ORDER BY count DESC
            """)
            
            severity_stats = cur.fetchall()
            
            return jsonify({
                "success": True,
                "summary": dict(stats) if stats else {},
                "by_severity": [dict(row) for row in severity_stats],
                "period": "last_24_hours"
            })
            
    except psycopg2.Error as e:
        return jsonify({"error": f"Error consultando estadísticas: {e}"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    print("🧪 SERVIDOR DE PRUEBA COMPLETO CON POSTGRESQL")
    print("=" * 70)
    print(f"🔗 Estado de BD: {'✅ Conectada' if BD_DISPONIBLE else '❌ No disponible'}")
    
    if BD_DISPONIBLE:
        # Verificar tablas importantes
        tables_check = {
            'users': verificar_tabla_existe('users'),
            'computing_devices': verificar_tabla_existe('computing_devices'),
            'federated_clients': verificar_tabla_existe('federated_clients'),
            'detections': verificar_tabla_existe('detections')
        }
        
        print("📋 Verificación de tablas:")
        for table, exists in tables_check.items():
            status = "✅" if exists else "❌"
            print(f"   {status} {table}")
    
    print("=" * 70)
    print("🚀 Iniciando servidor en http://localhost:5000")
    print("📡 Endpoints disponibles:")
    print("   GET  /health - Estado del servidor")
    print("   GET  /api/users/{user_id}/complete-info - Info del usuario")
    print("   POST /api/buffer/add-detection - Recibir detecciones")
    print("   GET  /api/mapping/info - Ver mapeo usuarios-dispositivos")
    print("   GET  /api/detections/recent - Detecciones recientes")
    print("   GET  /api/stats/summary - Estadísticas resumidas")
    print("=" * 70)
    print("⚠️ CARACTERÍSTICAS:")
    print("   ✅ Auto-creación de federated_clients")
    print("   ✅ Manejo robusto de errores")
    print("   ✅ Respaldo automático")
    print("   ✅ Verificación de estructura de tablas")
    print("=" * 70)
    
    app.run(host='0.0.0.0', port=5000, debug=False)