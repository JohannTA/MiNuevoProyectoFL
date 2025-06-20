from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_from_directory
from functools import wraps
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor
from collections import deque
from datetime import datetime
import psutil
import numpy as np  
import os
import jwt
import logging
import hashlib
import logging
import subprocess
import signal
import time
import json
import socket
import threading
import requests
import sys
import uuid
if sys.platform == 'win32':
    # Configurar UTF-8 para Windows
    import locale
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    if sys.stderr.encoding != 'utf-8':
        sys.stderr.reconfigure(encoding='utf-8')
detector_output_queue = []
federado_output_queue = []
detector_output_lock = threading.Lock()
federado_process = None 
detection_buffer_lock = threading.Lock()  
start_time = time.time() 
# Importaciones de controladores
from controladores.controlador_usuario import (
    obtener_usuario_por_id, autenticar_usuario, registrar_actividad_usuario, 
    listar_usuarios, crear_usuario, actualizar_usuario, eliminar_usuario, 
    cambiar_contrasena_usuario
)
from controladores.controlador_detecciones import (
    obtener_detecciones, obtener_deteccion_por_id, actualizar_deteccion, 
    obtener_estadisticas_detecciones, obtener_tipos_ataque, obtener_total_detecciones
)
from controladores.controlador_clientes import (
    obtener_clientes, obtener_cliente_por_id, crear_cliente, 
    actualizar_cliente, regenerar_api_key, eliminar_cliente
)
from controladores.controlador_reportes import (
    generar_reporte_detecciones, generar_reporte_clientes, 
    generar_reporte_rendimiento, exportar_reporte_csv
)
from controladores.controlador_dashboard import (
    obtener_datos_dashboard, obtener_resumen_mock, obtener_metricas_rendimiento
)
from controladores.controlador_sistema import obtener_logs_sistema, obtener_configuracion_sistema, actualizar_configuracion_sistema
from controladores.controlador_roles import (
    obtener_roles, obtener_permisos, obtener_permisos_rol, crear_rol,
    actualizar_rol, eliminar_rol, asignar_permisos_rol, crear_permiso, eliminar_permiso,
    verificar_permiso_usuario, inicializar_permisos_sistema
)
from controladores.controlador_detector import (
     normalizar_severity, procesar_deteccion_entrante, obtener_usuario_completo_con_dispositivo,
    obtener_mapeo_usuarios_dispositivos, obtener_health_check_extendido
)
# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.INFO)

# Inicializar la aplicación Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'clave_secreta_por_defecto')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt_clave_secreta')
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=2)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Asegurar que el directorio de uploads exista
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Variables globales para procesos
detector_process = None
federado_process = None
detector_stats = {
    'status': 'stopped',
    'interface': 'Ethernet',
    'packets': 0,
    'flows': 0,
    'uptime': 0,
    'detections': {'normal': 0, 'suspicious': 0, 'attack': 0}
}
federado_stats = {
    'status': 'stopped',
    'server': 'ws://localhost:8765',
    'clients': 0,
    'models': 0,
    'last_sync': None,
    'shared': 0,
    'received': 0,
    'accuracy': 0
}

# ========================================
# SISTEMA DE BUFFER TEMPORAL
# ========================================

# Instancia global del buffer de detecciones
def normalizar_severity(severity):
    """Normaliza el severity a valores válidos para la BD"""
    if not severity:
        return 'medium'
    
    severity_lower = str(severity).lower()
    
    if severity_lower in ['low', 'bajo', 'minor']:
        return 'low'
    elif severity_lower in ['medium', 'medio', 'moderate']:
        return 'medium'
    elif severity_lower in ['high', 'alto', 'major', 'critical']:
        return 'high'
    elif severity_lower in ['critical', 'critico', 'severe']:
        return 'critical'
    else:
        return 'medium'

@app.route('/api/users/<int:user_id>/complete-info', methods=['GET'])
def get_user_complete_info(user_id):
    """Endpoint para obtener información completa del usuario con dispositivo"""
    try:
        user_data = obtener_usuario_completo_con_dispositivo(user_id)
        
        if user_data and user_data['user']:
            if user_data['computing_device']:
                logger.info(f"Usuario encontrado: {user_data['user']['username']} con dispositivo asignado")
                return jsonify({"success": True, **user_data})
            else:
                return jsonify({"success": False, "error": f"Usuario no tiene dispositivo de cómputo asignado"}), 400
        else:
            return jsonify({"success": False, "error": f"Usuario ID {user_id} no encontrado"}), 404
            
    except Exception as e:
        logger.error(f"Error obteniendo info completa del usuario: {e}")
        return jsonify({"success": False, "error": "Error interno del servidor"}), 500



@app.route('/api/mapping/info', methods=['GET'])
def mapping_info():
    """Endpoint para ver el mapeo de usuarios-dispositivos-federated_clients"""
    result = obtener_mapeo_usuarios_dispositivos()
    
    if "error" in result:
        return jsonify(result), 500
    
    return jsonify(result)

@app.route('/health-extended', methods=['GET'])
def health_check_extended():
    """Endpoint de salud extendido del servidor"""
    result = obtener_health_check_extendido()
    
    # Agregar info de procesos locales
    detector_running = detector_process is not None and detector_process.poll() is None
    federado_running = federado_process is not None and federado_process.poll() is None
    
    result.update({
        "processes": {
            "detector_running": detector_running,
            "federado_running": federado_running
        },
        "buffer": detection_buffer.get_stats()
    })
    
    if "error" in result:
        return jsonify(result), 500
    
    return jsonify(result)
# ========================================
# BUFFER PARA ESTADÍSTICAS EN TIEMPO REAL
# ========================================

class StatsBuffer:
    """Buffer para estadísticas en tiempo real (no persistentes)"""
    
    def __init__(self):
        self.stats = {
            'detections_count': 0,
            'detections_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'detections_by_type': {},
            'recent_detections': deque(maxlen=50),  # Últimas 50 detecciones
            'hourly_stats': {},
            'start_time': time.time()
        }
        self.stats_lock = threading.Lock()
    
    def add_detection(self, detection):
        """Actualiza estadísticas en tiempo real"""
        with self.stats_lock:
            # Contador total
            self.stats['detections_count'] += 1
            
            # Por severidad
            severity = detection.get('severity', 'medium')
            if severity in self.stats['detections_by_severity']:
                self.stats['detections_by_severity'][severity] += 1
            
            # Por tipo
            anomaly_type = detection.get('anomaly_type', 'Unknown')
            if anomaly_type not in self.stats['detections_by_type']:
                self.stats['detections_by_type'][anomaly_type] = 0
            self.stats['detections_by_type'][anomaly_type] += 1
            
            # Detecciones recientes
            detection['display_time'] = datetime.datetime.datetime.now().isoformat()
            self.stats['recent_detections'].appendleft(detection)
            
            # Estadísticas por hora
            current_hour = datetime.now().hour
            if current_hour not in self.stats['hourly_stats']:
                self.stats['hourly_stats'][current_hour] = 0
            self.stats['hourly_stats'][current_hour] += 1
    
    def get_stats(self):
        """Obtiene estadísticas actuales"""
        with self.stats_lock:
            return {
                'total_detections': self.stats['detections_count'],
                'detections_by_severity': dict(self.stats['detections_by_severity']),
                'detections_by_type': dict(self.stats['detections_by_type']),
                'recent_detections': list(self.stats['recent_detections'])[:10],  # Solo últimas 10
                'uptime_seconds': time.time() - self.stats['start_time'],
                'hourly_stats': dict(self.stats['hourly_stats'])
            }
    
    def reset_stats(self):
        """Reinicia estadísticas (útil para testing)"""
        with self.stats_lock:
            self.stats['detections_count'] = 0
            self.stats['detections_by_severity'] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            self.stats['detections_by_type'] = {}
            self.stats['recent_detections'].clear()
            self.stats['hourly_stats'] = {}

# Instancia global del buffer de estadísticas
stats_buffer = StatsBuffer()
#---------------------------------------------------------
# Decoradores para protección de rutas
#---------------------------------------------------------

def login_required(f):
    """Decorador para requerir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicie sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user = obtener_usuario_por_id(session['user_id'])
        if not user or user['role'] != 'admin':
            flash('No tiene permisos para acceder a esta sección.', 'danger')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def supervisor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicie sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user = obtener_usuario_por_id(session['user_id'])
        if not user or user['role'] not in ['admin', 'supervisor']:
            flash('No tiene permisos para acceder a esta sección.', 'danger')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

#---------------------------------------------------------
# Rutas de autenticación
#---------------------------------------------------------

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redireccionar si el usuario ya está en sesión
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validación básica de campos
        if not username or not password:
            error = 'Por favor ingrese usuario y contraseña'
            return render_template('login.html', error=error)
        
        try:
            # Autenticar usuario usando el controlador
            user_data = autenticar_usuario(username, password)
            
            if user_data:
                # Guardar información en sesión
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['role'] = user_data['role']
                
                # Crear token JWT para API
                token_payload = {
                    'user_id': user_data['id'],
                    'username': user_data['username'],
                    'role': user_data['role'],
                    'exp': datetime.datetime.now(datetime.timezone.utc) + app.config['JWT_EXPIRATION_DELTA']
                }
                token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
                
                # Guardar token en sesión para uso en la aplicación
                session['jwt_token'] = token
                
                # Recordar sesión si se seleccionó la opción
                if request.form.get('remember'):
                    session.permanent = True
                
                # Registrar actividad de login
                registrar_actividad_usuario(
                    user_data['id'],
                    'login',
                    'Inicio de sesión exitoso',
                    request.remote_addr
                )
                
                # Mensaje de éxito y redirección
                flash(f'Bienvenido {user_data["username"]}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                error = 'Usuario o contraseña incorrectos'
                logger.warning(f'Intento de inicio de sesión fallido para el usuario: {username}')
        except Exception as e:
            logger.error(f"Error en el proceso de autenticación: {e}")
            error = 'Ocurrió un error en el servidor. Por favor intente nuevamente.'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Registrar actividad de logout
        registrar_actividad_usuario(
            session['user_id'],
            'logout',
            'Cierre de sesión exitoso',
            request.remote_addr
        )
    
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

@app.route('/cambiar_contrasena', methods=['POST'])
@login_required
def cambiar_contrasena():
    actual = request.form.get('actual')
    nueva = request.form.get('nueva')
    confirmar = request.form.get('confirmar')
    
    if not actual or not nueva or not confirmar:
        flash('Todos los campos son obligatorios', 'warning')
        return redirect(url_for('dashboard'))
    
    if nueva != confirmar:
        flash('Las contraseñas nuevas no coinciden', 'warning')
        return redirect(url_for('dashboard'))
    
    # Verificar que la longitud mínima sea adecuada
    if len(nueva) < 8:
        flash('La contraseña nueva debe tener al menos 8 caracteres', 'warning')
        return redirect(url_for('dashboard'))
    
    # Implementar cambio de contraseña
    exito = cambiar_contrasena_usuario(session['user_id'], actual, nueva)
    
    if exito:
        flash('Contraseña actualizada exitosamente', 'success')
        registrar_actividad_usuario(
            session['user_id'],
            'cambiar_contrasena',
            'Contraseña actualizada',
            request.remote_addr
        )
    else:
        flash('Error al actualizar la contraseña. Verifique su contraseña actual.', 'danger')
    
    return redirect(url_for('dashboard'))

#---------------------------------------------------------
# Rutas principales de la aplicación
#---------------------------------------------------------

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Obtener datos del usuario
        user = obtener_usuario_por_id(session['user_id'])
        if not user:
            flash('Error al obtener información del usuario', 'danger')
            return redirect(url_for('login'))
        
        # Obtener datos del dashboard
        datos_dashboard = obtener_datos_dashboard()
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'access_dashboard',
            'Acceso al dashboard principal',
            request.remote_addr
        )
        
        return render_template('dashboard.html', 
                             user=user, 
                             datos=datos_dashboard)
        
    except Exception as e:
        logger.error(f"Error en dashboard: {e}")
        flash('Error al cargar el dashboard', 'danger')
        return render_template('dashboard.html', 
                             user={'username': session.get('username', 'Usuario')}, 
                             datos={})

#---------------------------------------------------------
# RUTAS DE API TIEMPO REAL
#---------------------------------------------------------
@app.route('/api/detector/status')
@login_required
def get_detector_status():
    """Obtiene el estado del detector con estadísticas detalladas"""
    global detector_process
    
    # Verificar si el proceso sigue activo
    if detector_process and detector_process.poll() is not None:
        detector_stats['status'] = 'stopped'
        detector_process = None
    
    # Calcular uptime si está corriendo
    if detector_stats['status'] == 'running' and 'start_time' in detector_stats:
        detector_stats['uptime'] = int(time.time() - detector_stats['start_time'])
    else:
        detector_stats['uptime'] = 0
    
    # Intentar obtener estadísticas de la BD si está disponible
    try:
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                # Estadísticas de detecciones recientes
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_detections,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') as detections_1h,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as detections_24h,
                        COUNT(*) FILTER (WHERE severity = 'high') as high_severity,
                        COUNT(*) FILTER (WHERE severity = 'critical') as critical_alerts,
                        COUNT(DISTINCT source_ip) as unique_sources,
                        COUNT(DISTINCT destination_ip) as unique_destinations
                    FROM detections 
                    WHERE client_id = %s
                """, (detector_stats.get('client_id', 1),))
                
                result = cursor.fetchone()
                if result:
                    detector_stats['detections'] = {
                        'total': result[0],
                        'last_hour': result[1],
                        'last_24h': result[2],
                        'high_severity': result[3],
                        'critical': result[4],
                        'unique_sources': result[5],
                        'unique_destinations': result[6]
                    }
                
                # Últimas detecciones para mostrar actividad
                cursor.execute("""
                    SELECT anomaly_type, severity, confidence_score, timestamp
                    FROM detections 
                    WHERE client_id = %s AND timestamp >= NOW() - INTERVAL '1 hour'
                    ORDER BY timestamp DESC
                    LIMIT 10
                """, (detector_stats.get('client_id', 1),))
                
                recent_detections = []
                for row in cursor.fetchall():
                    recent_detections.append({
                        'type': row[0],
                        'severity': row[1], 
                        'score': float(row[2]) if row[2] else 0,
                        'timestamp': row[3].isoformat() if row[3] else None
                    })
                
                detector_stats['recent_activity'] = recent_detections
            
            conn.close()
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas del detector: {e}")
        # Valores por defecto si hay error
        detector_stats['detections'] = {
            'total': 0, 'last_hour': 0, 'last_24h': 0,
            'high_severity': 0, 'critical': 0,
            'unique_sources': 0, 'unique_destinations': 0
        }
        detector_stats['recent_activity'] = []
    
    return jsonify({'stats': detector_stats})
@app.route('/api/realtime/stats')
@login_required
def get_realtime_stats():
    """Obtiene estadísticas en tiempo real para el dashboard"""
    try:
        conn = obtener_conexion()
        
        # Estadísticas base si no hay BD
        stats_base = {
            'total_detecciones': 0,
            'detecciones_1h': 0,
            'detecciones_24h': 0,
            'alertas_criticas': 0,
            'clientes_detectando': 0,
            'total_clientes': 0,
            'clientes_activos': 0
        }
        
        if conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Estadísticas básicas de detecciones
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_detecciones,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') as detecciones_1h,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as detecciones_24h,
                        COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) as alertas_criticas,
                        COUNT(DISTINCT client_id) as clientes_detectando
                    FROM detections
                """)
                
                stats_row = cursor.fetchone()
                if stats_row:
                    stats_base.update(dict(stats_row))
                
                # Estados de clientes federados
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_clientes,
                        COUNT(*) FILTER (WHERE status = 'active' AND last_seen >= NOW() - INTERVAL '5 minutes') as clientes_activos
                    FROM federated_clients
                """)
                
                clientes_row = cursor.fetchone()
                if clientes_row:
                    stats_base.update(dict(clientes_row))
                
                # Distribución por severidad (última hora)
                cursor.execute("""
                    SELECT 
                        COALESCE(severity, 'unknown') as severity, 
                        COUNT(*) as count
                    FROM detections 
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                    GROUP BY severity
                """)
                
                severidad_1h = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Tipos de ataque (última hora)
                cursor.execute("""
                    SELECT 
                        COALESCE(anomaly_type, 'Desconocido') as tipo,
                        COUNT(*) as count
                    FROM detections 
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                    GROUP BY anomaly_type
                    ORDER BY count DESC
                    LIMIT 5
                """)
                
                tipos_ataque_1h = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
        else:
            # Si no hay BD, usar datos del detector en memoria si está corriendo
            if detector_process and detector_process.poll() is None:
                # Simular datos básicos del detector activo
                stats_base.update({
                    'total_detecciones': detector_stats.get('detections', {}).get('total', 0),
                    'detecciones_24h': detector_stats.get('detections', {}).get('last_hour', 0),
                    'alertas_criticas': detector_stats.get('detections', {}).get('critical', 0),
                    'clientes_activos': 1 if detector_stats.get('status') == 'running' else 0
                })
            
            severidad_1h = {}
            tipos_ataque_1h = []
        
        # Combinar con estados de procesos locales
        detector_running = detector_process is not None and detector_process.poll() is None
        federado_running = federado_process is not None and federado_process.poll() is None
        
        # Si hay detector corriendo, incrementar clientes activos
        if detector_running and stats_base['clientes_activos'] == 0:
            stats_base['clientes_activos'] = 1
            stats_base['total_clientes'] = max(1, stats_base['total_clientes'])
        
        response_data = {
            'timestamp': datetime.datetime.datetime.now().isoformat(),
            'resumen': stats_base,
            'severidad_1h': severidad_1h,
            'tipos_ataque_1h': tipos_ataque_1h,
            'system_status': {
                'detector_running': detector_running,
                'federado_running': federado_running,
                'detector_stats': detector_stats.copy(),
                'federado_stats': federado_stats.copy()
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error en stats tiempo real: {e}")
        # Retornar datos básicos en caso de error
        return jsonify({
            'timestamp': datetime.datetime.datetime.now().isoformat(),
            'resumen': {
                'total_detecciones': detector_stats.get('detections', {}).get('total', 0),
                'detecciones_1h': 0,
                'detecciones_24h': detector_stats.get('detections', {}).get('last_hour', 0),
                'alertas_criticas': detector_stats.get('detections', {}).get('critical', 0),
                'clientes_detectando': 0,
                'total_clientes': 1 if detector_process and detector_process.poll() is None else 0,
                'clientes_activos': 1 if detector_process and detector_process.poll() is None else 0
            },
            'severidad_1h': {},
            'tipos_ataque_1h': [],
            'error': 'Datos limitados disponibles'
        })
@app.route('/api/realtime/detections')
@login_required
def get_realtime_detections():
    """Obtiene últimas detecciones en tiempo real"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'error': 'Sin conexión BD'}), 500
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    d.detection_id as id,
                    d.timestamp,
                    COALESCE(d.source_ip, '0.0.0.0') as source_ip,
                    COALESCE(d.destination_ip, '0.0.0.0') as destination_ip,
                    COALESCE(d.source_port, 0) as source_port,
                    COALESCE(d.destination_port, 0) as destination_port,
                    COALESCE(d.protocol, 'TCP') as protocol,
                    COALESCE(d.anomaly_type, 'Desconocido') as anomaly_type,
                    COALESCE(d.severity, 'medium') as severity,
                    COALESCE(d.confidence_score, 0.5) as confidence_score,
                    COALESCE(fc.name, 'Cliente ' || CAST(d.client_id AS TEXT)) as client_name,
                    d.is_confirmed,
                    COALESCE(d.false_positive, false) as false_positive,
                    EXTRACT(EPOCH FROM d.timestamp) as timestamp_unix
                FROM detections d
                LEFT JOIN federated_clients fc ON CAST(d.client_id AS TEXT) = CAST(fc.client_id AS TEXT)
                ORDER BY d.timestamp DESC
                LIMIT %s
            """, (limit,))
            
            detections = []
            for row in cursor.fetchall():
                detection = dict(row)
                if detection['timestamp']:
                    detection['timestamp'] = detection['timestamp'].isoformat()
                detections.append(detection)
            
        conn.close()
        return jsonify({'detections': detections})
        
    except Exception as e:
        logger.error(f"Error obteniendo detecciones tiempo real: {e}")
        return jsonify({'error': 'Error interno'}), 500

#---------------------------------------------------------
# RUTAS DE CONTROL DE DETECTOR Y FEDERADO
#---------------------------------------------------------
def capture_detector_output(process):
    """Captura la salida del proceso detector en tiempo real"""
    global detector_output_queue, detector_output_lock
    
    try:
        while True:
            line = process.stdout.readline()
            if not line:
                # Proceso terminó
                break
            
            line = line.strip()
            if line:
                # Agregar timestamp y limpiar línea
                timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                
                # Procesar línea para extraer información útil
                processed_line = {
                    'timestamp': timestamp,
                    'raw': line,
                    'type': 'info'
                }
                
                # Clasificar tipo de mensaje basado en palabras clave
                line_upper = line.upper()
                if any(keyword in line_upper for keyword in ['ERROR', 'FAILED', 'EXCEPTION']):
                    processed_line['type'] = 'error'
                elif any(keyword in line_upper for keyword in ['WARNING', 'WARN']):
                    processed_line['type'] = 'warning'
                elif any(keyword in line_upper for keyword in ['ATTACK', 'ATAQUE', 'SUSPICIOUS', 'SOSPECHOSO']):
                    processed_line['type'] = 'alert'
                elif any(keyword in line_upper for keyword in ['INFO', 'STARTED', 'INICIADO', 'SUCCESS', 'OK']):
                    processed_line['type'] = 'success'
                elif any(keyword in line_upper for keyword in ['NORMAL', 'TRÁFICO']):
                    processed_line['type'] = 'normal'
                
                # Agregar a cola con thread safety
                # Lock eliminado - no necesario
                    detector_output_queue.append(processed_line)
                    # Mantener últimas 200 líneas
                    if len(detector_output_queue) > 200:
                        detector_output_queue.pop(0)
                
                # También imprimir en el log del servidor para debugging
                logger.info(f"[DETECTOR] {line}")
                
    except Exception as e:
        logger.error(f"Error capturando salida del detector: {e}")
        # Lock eliminado - no necesario
            detector_output_queue.append({
                'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
                'raw': f"Error capturando salida: {str(e)}",
                'type': 'error'
            })
    finally:
        logger.info("Captura de salida del detector terminada")
        # Lock eliminado - no necesario
            detector_output_queue.append({
                'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
                'raw': "--- Proceso detector terminado ---",
                'type': 'warning'
            })
 
@app.route('/api/detector/start', methods=['POST'])
@login_required
def start_detector():
    """Inicia el detector integrado federado"""
    global detector_process
    
    try:
        data = request.get_json() or {}
        user_id = session.get('client_id', 1)
        interface = data.get('interface', 'Wi-Fi')
        servidor_federado = data.get('servidor_federado', 'ws://192.168.18.88:8765')
        if detector_process and detector_process.poll() is None:
            return jsonify({'error': 'El detector ya está ejecutándose'}), 400
        
        # Verificar archivos necesarios
        if not os.path.exists('detector_integrado.py'):
            return jsonify({'error': 'detector_integrado.py no encontrado'}), 500
        
        # Buscar modelo disponible
        model_path = 'model/modelo_rf.pkl'
        if not os.path.exists(model_path):
            model_path = 'model/modelo_rf_optimizado.pkl'
        if not os.path.exists(model_path):
            return jsonify({'error': 'Modelo no encontrado'}), 500
        
        # Comando SIMPLIFICADO para detector integrado
        cmd = [
            sys.executable, 'detector_integrado.py',
            '--user-id', str(user_id),
            '--interface', interface,
            '--model', model_path,
            '--flask-url', 'http://localhost:5000',
            '--servidor-federado', servidor_federado
        ]
        
        # MENSAJE EN CONSOLA
        print(f"\n{'='*80}")
        print(f"🚀 INICIANDO DETECTOR INTEGRADO FEDERADO")
        print(f"{'='*80}")
        print(f"👤 Usuario ID: {user_id}")
        print(f"🌐 Interfaz: {interface}")
        print(f"🤖 Modelo: {model_path}")
        print(f"🔗 Flask URL: http://localhost:5000")
        print(f"🔧 Comando: {' '.join(cmd)}")
        print(f"{'='*80}")
        
        # Limpiar buffer de salida
        # Lock eliminado - no necesario
            detector_output_queue.clear()
        
        # EJECUTAR SIN CAPTURAR STDOUT (para ver toda la salida)
        detector_process = subprocess.Popen(
            cmd,
            # stdout=None,      # Salida directa a consola
            # stderr=None,      # Errores directos a consola
            stdout=subprocess.PIPE,  # Para API también
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # Sin buffer
            universal_newlines=True,
            cwd=os.getcwd()
        )
        
        # Captura EN TIEMPO REAL para API (sin interferir con consola)
        def capture_for_api():
            try:
                for line in iter(detector_process.stdout.readline, ''):
                    if line.strip():
                        # Mostrar en consola principal
                        print(f"[DETECTOR] {line.rstrip()}")
                        
                        # También guardar para API
                        # Lock eliminado - no necesario
                            detector_output_queue.append({
                                'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
                                'raw': line.strip(),
                                'type': 'output'
                            })
                            # Limitar tamaño
                            if len(detector_output_queue) > 500:
                                detector_output_queue.pop(0)
            except Exception as e:
                print(f"❌ Error en captura: {e}")
        
        # Iniciar captura en hilo separado
        threading.Thread(target=capture_for_api, daemon=True).start()
        
        print(f"✅ Detector iniciado con PID: {detector_process.pid}")
        print(f"📡 Salida visible en tiempo real en esta consola")
        print(f"{'='*80}\n")
        
        # Actualizar estadísticas
        detector_stats['status'] = 'running'
        detector_stats['interface'] = interface
        detector_stats['user_id'] = user_id
        detector_stats['start_time'] = time.time()
        detector_stats['pid'] = detector_process.pid
        
        return jsonify({
            'success': True,
            'message': f'Detector federado iniciado - salida en consola',
            'pid': detector_process.pid,
            'interface': interface,
            'user_id': user_id,
            'model_path': model_path,
            'flask_url': 'http://localhost:5000'
        })
        
    except Exception as e:
        print(f"❌ Error iniciando detector: {e}")
        logger.error(f"Error iniciando detector: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/detector/stop', methods=['POST'])
@login_required
def stop_detector():
    """Detiene el detector de flujos"""
    global detector_process
    
    try:
        if not detector_process or detector_process.poll() is not None:
            return jsonify({'error': 'El detector no está ejecutándose'}), 400
        
        # Intentar terminar el proceso suavemente
        detector_process.terminate()
        
        try:
            # Esperar 5 segundos para que termine
            detector_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Si no termina, forzar la terminación
            detector_process.kill()
            detector_process.wait()
        
        # Actualizar stats
        detector_stats['status'] = 'stopped'
        if 'start_time' in detector_stats:
            del detector_stats['start_time']
        
        detector_process = None
        
        logger.info("Detector detenido")
        
        return jsonify({
            'success': True,
            'message': 'Detector detenido correctamente',
            'stats': detector_stats
        })
        
    except Exception as e:
        logger.error(f"Error deteniendo detector: {e}")
        return jsonify({'error': f'Error deteniendo detector: {str(e)}'}), 500


@app.route('/api/detector/output')
@login_required
def get_detector_output():
    """Obtiene la salida del detector"""
    global detector_output_queue, detector_output_lock
    
    try:
        # Obtener líneas desde un índice específico
        since = request.args.get('since', 0, type=int)
        
        # Lock eliminado - no necesario
            # Retornar líneas desde el índice solicitado
            lines = detector_output_queue[since:] if since < len(detector_output_queue) else []
            total_lines = len(detector_output_queue)
        
        # Verificar si el proceso sigue corriendo
        is_running = detector_process is not None and detector_process.poll() is None
        
        return jsonify({
            'lines': lines,
            'total': total_lines,
            'since': since,
            'running': is_running,
            'timestamp': datetime.datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo salida del detector: {e}")
        return jsonify({'error': 'Error obteniendo salida'}), 500
    
@app.route('/api/federado/start', methods=['POST'])
@login_required
def start_federado():
    """Inicia el servidor federado"""
    global federado_process
    
    try:
        data = request.get_json() or {}
        host = data.get('host', '0.0.0.0')
        port = data.get('port', 8765)
        min_clients = data.get('min_clients', 1)
        
        if federado_process and federado_process.poll() is None:
            return jsonify({'error': 'El servidor federado ya está ejecutándose'}), 400
        
        if not os.path.exists('servidor_federado.py'):
            return jsonify({'error': 'Archivo servidor_federado.py no encontrado'}), 500
        
        # Comando CORREGIDO para servidor federado
        cmd = [
            sys.executable, 'servidor_federado.py',
            '--host', host,
            '--port', str(port),
            '--min-clients', str(min_clients)
        ]
        
        logger.info(f"Ejecutando servidor federado: {' '.join(cmd)}")
        
        federado_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=os.getcwd()
        )
        
        # Actualizar stats
        federado_stats['status'] = 'running'
        federado_stats['host'] = host
        federado_stats['port'] = port
        federado_stats['server'] = f'ws://{host}:{port}'
        federado_stats['start_time'] = time.time()
        
        logger.info(f"Servidor federado iniciado en {host}:{port}")
        
        return jsonify({
            'success': True,
            'message': f'Servidor federado iniciado en {host}:{port}',
            'pid': federado_process.pid,
            'config': {
                'host': host,
                'port': port,
                'min_clients': min_clients,
                'server_url': f'ws://{host}:{port}'
            },
            'stats': federado_stats
        })
        
    except Exception as e:
        logger.error(f"Error iniciando servidor federado: {e}")
        return jsonify({'error': f'Error iniciando servidor federado: {str(e)}'}), 500

@app.route('/api/federado/stop', methods=['POST'])
@login_required
def stop_federado():
    """Detiene el servidor federado"""
    global federado_process
    
    try:
        if not federado_process or federado_process.poll() is not None:
            return jsonify({'error': 'El servidor federado no está ejecutándose'}), 400
        
        # Intentar terminar el proceso suavemente
        federado_process.terminate()
        
        try:
            # Esperar 5 segundos para que termine
            federado_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Si no termina, forzar la terminación
            federado_process.kill()
            federado_process.wait()
        
        # Actualizar stats
        federado_stats['status'] = 'stopped'
        if 'start_time' in federado_stats:
            del federado_stats['start_time']
        
        federado_process = None
        
        logger.info("Servidor federado detenido")
        
        return jsonify({
            'success': True,
            'message': 'Servidor federado detenido correctamente',
            'stats': federado_stats
        })
        
    except Exception as e:
        logger.error(f"Error deteniendo servidor federado: {e}")
        return jsonify({'error': f'Error deteniendo servidor federado: {str(e)}'}), 500

@app.route('/api/federado/status')
@login_required
def get_federado_status():
    """Obtiene el estado del servidor federado"""
    global federado_process
    
    # Verificar si el proceso sigue activo
    if federado_process and federado_process.poll() is not None:
        federado_stats['status'] = 'stopped'
        federado_process = None
    
    # Calcular uptime si está corriendo
    if federado_stats['status'] == 'running' and 'start_time' in federado_stats:
        federado_stats['uptime'] = int(time.time() - federado_stats['start_time'])
    else:
        federado_stats['uptime'] = 0
    
    # Intentar obtener estadísticas de clientes federados
    try:
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                # Contar clientes federados activos
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_clients,
                        COUNT(*) FILTER (WHERE status = 'active') as active_clients,
                        MAX(last_seen) as last_activity
                    FROM federated_clients
                """)
                
                result = cursor.fetchone()
                if result:
                    federado_stats['clients'] = result[1] or 0
                    federado_stats['total_clients'] = result[0] or 0
                    federado_stats['last_activity'] = result[2]
            conn.close()
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas del federado: {e}")
    
    return jsonify({'stats': federado_stats})
# ========================================
# ENDPOINTS PARA APRENDIZAJE FEDERADO
# ========================================

@app.route('/api/federado/model-update', methods=['POST'])
@login_required
def receive_model_update():
    """Recibe actualización de modelo de un cliente federado"""
    try:
        data = request.get_json()
        
        client_id = data.get('client_id')
        user_id = data.get('user_id') 
        model_weights = data.get('model_weights')
        performance_metrics = data.get('performance_metrics')
        training_samples = data.get('training_samples', 0)
        device_info = data.get('device_info', {})
        
        print(f"📥 [FEDERADO] Actualización modelo recibida:")
        print(f"   Cliente: {client_id}, Usuario: {user_id}")
        print(f"   Muestras entrenamiento: {training_samples}")
        print(f"   Métricas: {performance_metrics}")
        
        # Aquí implementarías la lógica de agregación federada
        # Por ahora solo logueamos
        
        logger.info(f"Actualización modelo recibida de cliente {client_id}, usuario {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Actualización de modelo recibida y procesada',
            'client_id': client_id,
            'user_id': user_id,
            'aggregation_pending': True,
            'timestamp': datetime.datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error recibiendo actualización modelo: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/federado/global-model', methods=['GET'])
@login_required
def send_global_model():
    """Envía el modelo global actualizado a un cliente"""
    try:
        client_id = request.args.get('client_id')
        user_id = request.args.get('user_id')
        
        print(f"📤 [FEDERADO] Enviando modelo global a cliente {client_id}, usuario {user_id}")
        
        # Aquí implementarías la lógica para obtener el modelo global
        # Por ahora devolvemos un modelo mock
        model_data = {
            'version': 1,
            'weights': 'model_weights_serialized',  # Implementar serialización real
            'performance': {
                'accuracy': 0.95, 
                'precision': 0.93,
                'recall': 0.91,
                'f1_score': 0.92
            },
            'last_updated': datetime.datetime.datetime.now().isoformat(),
            'clients_contributed': 1,  # Contar clientes reales
            'training_rounds': 1,
            'metadata': {
                'model_type': 'RandomForest',
                'features_count': 78,
                'classes': ['normal', 'attack']
            }
        }
        
        logger.info(f"Modelo global enviado a cliente {client_id}, usuario {user_id}")
        
        return jsonify({
            'success': True,
            'model_data': model_data,
            'client_id': client_id,
            'user_id': user_id,
            'download_timestamp': datetime.datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error enviando modelo global: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


    
@app.route('/api/system/log')
@login_required
def get_system_log():
    """Obtiene el log del sistema"""
    try:
        log_entries = []
        
        # Log de la aplicación principal
        if os.path.exists('app.log'):
            with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines[-50:]:
                    if line.strip():
                        log_entries.append({
                            'timestamp': datetime.datetime.datetime.now().isoformat(),
                            'component': 'Sistema',
                            'level': 'INFO',
                            'message': line.strip()
                        })
        
        # Si no hay logs, agregar datos de ejemplo
        if not log_entries:
            log_entries = [
                {
                    'timestamp': datetime.datetime.datetime.now().isoformat(),
                    'component': 'Sistema',
                    'level': 'INFO',
                    'message': 'Sistema IDS iniciado correctamente'
                }
            ]
        
        log_entries.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({'log_entries': log_entries[:100]})
        
    except Exception as e:
        logger.error(f"Error obteniendo log: {e}")
        return jsonify({'error': 'Error obteniendo log'}), 500

@app.route('/api/system/interfaces')
@login_required
def get_network_interfaces():
    """Obtiene interfaces de red disponibles"""
    try:
        interfaces = []
        
        # Obtener todas las interfaces de red
        for interface_name, addresses in psutil.net_if_addrs().items():
            # Filtrar interfaces inútiles
            if interface_name in ['Loopback Pseudo-Interface 1', 'lo', 'Loopback']:
                continue
            
            interface_info = {
                'name': interface_name,
                'display_name': interface_name,
                'addresses': [],
                'is_up': False,
                'speed': 'Unknown',
                'type': 'Unknown'
            }
            
            # Obtener direcciones IPv4
            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    interface_info['addresses'].append(addr.address)
            
            # Solo incluir interfaces con direcciones IPv4 válidas
            if interface_info['addresses']:
                # Verificar si la interfaz está activa
                try:
                    net_if_stats = psutil.net_if_stats()
                    if interface_name in net_if_stats:
                        stats = net_if_stats[interface_name]
                        interface_info['is_up'] = stats.isup
                        interface_info['speed'] = f"{stats.speed} Mbps" if stats.speed > 0 else "Unknown"
                        
                        # Determinar tipo de interfaz
                        name_lower = interface_name.lower()
                        if 'wifi' in name_lower or 'wireless' in name_lower or 'wi-fi' in name_lower:
                            interface_info['type'] = 'Wi-Fi'
                        elif 'ethernet' in name_lower or 'local' in name_lower:
                            interface_info['type'] = 'Ethernet'
                        elif 'bluetooth' in name_lower:
                            interface_info['type'] = 'Bluetooth'
                        else:
                            interface_info['type'] = 'Other'
                        
                        # Mejorar nombre para mostrar
                        if interface_info['type'] != 'Other':
                            interface_info['display_name'] = f"{interface_info['type']} ({interface_name})"
                        
                except Exception as e:
                    logger.debug(f"Error obteniendo stats de {interface_name}: {e}")
                
                interfaces.append(interface_info)
        
        # Ordenar por tipo y estado (activas primero)
        interfaces.sort(key=lambda x: (not x['is_up'], x['type'], x['name']))
        
        logger.info(f"Detectadas {len(interfaces)} interfaces de red utilizables")
        
        return jsonify({
            'success': True,
            'interfaces': interfaces,
            'total_count': len(interfaces),
            'active_count': sum(1 for iface in interfaces if iface['is_up'])
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo interfaces: {e}")
        # Fallback con interfaces comunes
        fallback_interfaces = [
            {
                'name': 'Wi-Fi',
                'display_name': 'Wi-Fi (Adaptador inalámbrico)',
                'addresses': ['192.168.1.100'],
                'is_up': True,
                'speed': 'Unknown',
                'type': 'Wi-Fi'
            },
            {
                'name': 'Ethernet',
                'display_name': 'Ethernet (Conexión de área local)',
                'addresses': ['192.168.1.101'],
                'is_up': True,
                'speed': 'Unknown', 
                'type': 'Ethernet'
            }
        ]
        
        return jsonify({
            'success': True,
            'interfaces': fallback_interfaces,
            'total_count': len(fallback_interfaces),
            'active_count': len(fallback_interfaces),
            'fallback': True
        })

#---------------------------------------------------------
# RUTAS NUEVAS PARA LAS FUNCIONES DEL DASHBOARD
#---------------------------------------------------------

@app.route('/api/dashboard/verify-connection', methods=['POST'])
@login_required
def verificar_conexion():
    """Verifica la conectividad del sistema"""
    try:
        results = {
            'database': False,
            'detector': False,
            'federado': False,
            'network': False,
            'timestamp': datetime.datetime.datetime.now().isoformat()
        }
        
        # Verificar BD
        try:
            conn = obtener_conexion()
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
                results['database'] = True
                conn.close()
        except Exception as e:
            logger.error(f"Error verificando BD: {e}")
        
        # Verificar detector
        if detector_process and detector_process.poll() is None:
            results['detector'] = True
        
        # Verificar federado
        if federado_process and federado_process.poll() is None:
            results['federado'] = True
        
        # Verificar red
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            results['network'] = True
            sock.close()
        except Exception:
            pass
        
        return jsonify({
            'success': True,
            'results': results,
            'message': 'Verificación de conectividad completada'
        })
        
    except Exception as e:
        logger.error(f"Error verificando conexión: {e}")
        return jsonify({'error': 'Error verificando conexión'}), 500

@app.route('/api/dashboard/performance-check', methods=['POST'])
@login_required
def verificar_rendimiento():
    """Verifica el rendimiento del sistema"""
    try:
        # Usar ruta correcta para Windows
        try:
            disk_usage = psutil.disk_usage('C:' if sys.platform == 'win32' else '/')
            disk_percent = disk_usage.percent
        except:
            disk_percent = 0

        performance = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': disk_percent,
            'process_count': len(psutil.pids()),
            'timestamp': datetime.datetime.datetime.now().isoformat()
        }
        
        # Evaluación de rendimiento
        issues = []
        if performance['cpu_percent'] > 80:
            issues.append('CPU sobrecargada')
        if performance['memory_percent'] > 85:
            issues.append('Memoria baja')
        if performance['disk_percent'] > 90:
            issues.append('Espacio en disco bajo')
        
        status = 'good' if not issues else 'warning' if len(issues) <= 2 else 'critical'
        
        return jsonify({
            'success': True,
            'performance': performance,
            'status': status,
            'issues': issues,
            'message': f'Estado del sistema: {status}'
        })
        
    except Exception as e:
        logger.error(f"Error verificando rendimiento: {e}")
        return jsonify({'error': 'Error verificando rendimiento'}), 500

@app.route('/api/dashboard/diagnostics', methods=['POST'])
@login_required
def ejecutar_diagnosticos():
    """Ejecuta diagnósticos del sistema"""
    try:
        diagnostics = {
            'system_info': {
                'python_version': sys.version,
                'platform': sys.platform,
                'working_directory': os.getcwd()
            },
            'files_check': {
                'detector_integrado': os.path.exists('detector_integrado.py'),
                'servidor_federado': os.path.exists('servidor_federado.py'),
                'model_file': os.path.exists('model/modelo_rf.pkl'),
                'database_module': True  # Ya importado
            },
            'processes': {
                'detector_running': detector_process is not None and detector_process.poll() is None,
                'federado_running': federado_process is not None and federado_process.poll() is None
            },
            'timestamp': datetime.datetime.datetime.now().isoformat()
        }
        
        # Contar problemas
        problems = []
        if not diagnostics['files_check']['detector_integrado']:
            problems.append('Archivo detector_integrado.py no encontrado')
        if not diagnostics['files_check']['servidor_federado']:
            problems.append('Archivo servidor_federado.py no encontrado')
        if not diagnostics['files_check']['model_file']:
            problems.append('Archivo modelo ML no encontrado')
        
        status = 'healthy' if not problems else 'issues_found'
        
        return jsonify({
            'success': True,
            'diagnostics': diagnostics,
            'status': status,
            'problems': problems,
            'message': f'Diagnósticos completados - {status}'
        })
        
    except Exception as e:
        logger.error(f"Error ejecutando diagnósticos: {e}")
        return jsonify({'error': 'Error ejecutando diagnósticos'}), 500

@app.route('/api/dashboard/export-config', methods=['POST'])
@login_required
def exportar_configuracion():
    """Exporta la configuración del sistema"""
    try:
        config = {
            'detector': {
                'status': detector_stats['status'],
                'interface': detector_stats.get('interface', 'Wi-Fi'),
                'client_id': detector_stats.get('client_id', 1),
                'servidor_federado': detector_stats.get('servidor_federado', 'ws://localhost:8765')
            },
            'federado': {
                'status': federado_stats['status'],
                'host': federado_stats.get('host', '0.0.0.0'),
                'port': federado_stats.get('port', 8765),
                'server': federado_stats.get('server', 'ws://localhost:8765')
            },
            'export_info': {
                'timestamp': datetime.datetime.datetime.now().isoformat(),
                'exported_by': session['username'],
                'version': '1.0'
            }
        }
        
        return jsonify({
            'success': True,
            'config': config,
            'filename': f'ids_config_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            'message': 'Configuración exportada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error exportando configuración: {e}")
        return jsonify({'error': 'Error exportando configuración'}), 500

@app.route('/api/dashboard/import-config', methods=['POST'])
@login_required
def importar_configuracion():
    """Importa la configuración del sistema"""
    try:
        data = request.get_json()
        
        if not data or 'config' not in data:
            return jsonify({'error': 'Datos de configuración inválidos'}), 400
        
        config = data['config']
        
        # Actualizar configuración detector
        if 'detector' in config:
            detector_config = config['detector']
            detector_stats.update({
                'interface': detector_config.get('interface', detector_stats.get('interface')),
                'client_id': detector_config.get('client_id', detector_stats.get('client_id')),
                'servidor_federado': detector_config.get('servidor_federado', detector_stats.get('servidor_federado'))
            })
        
        # Actualizar configuración federado
        if 'federado' in config:
            federado_config = config['federado']
            federado_stats.update({
                'host': federado_config.get('host', federado_stats.get('host')),
                'port': federado_config.get('port', federado_stats.get('port')),
                'server': federado_config.get('server', federado_stats.get('server'))
            })
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'import_config',
            'Configuración importada',
            request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'message': 'Configuración importada exitosamente'
        })
        
    except Exception as e:
        logger.error(f"Error importando configuración: {e}")
        return jsonify({'error': 'Error importando configuración'}), 500

#---------------------------------------------------------
# Rutas básicas adicionales
#---------------------------------------------------------

@app.route('/detecciones')
@login_required
def detecciones():
    user = obtener_usuario_por_id(session['user_id'])
    try:
        detecciones_data = obtener_detecciones(limite=50)
        return render_template('detecciones.html', user=user, detecciones=detecciones_data)
    except Exception as e:
        logger.error(f"Error en detecciones: {e}")
        flash('Error al cargar detecciones', 'danger')
        return render_template('detecciones.html', user=user, detecciones=[])

@app.route('/clientes')
@login_required
def clientes():
    user = obtener_usuario_por_id(session['user_id'])
    try:
        lista_clientes = obtener_clientes()
        return render_template('clientes.html', user=user, clientes=lista_clientes)
    except Exception as e:
        logger.error(f"Error en clientes: {e}")
        flash('Error al cargar clientes', 'danger')
        return render_template('clientes.html', user=user, clientes=[])

@app.route('/reportes')
@login_required
def reportes():
    user = obtener_usuario_por_id(session['user_id'])
    try:
        return render_template('reportes.html', user=user)
    except Exception as e:
        logger.error(f"Error en reportes: {e}")
        flash('Error al cargar reportes', 'danger')
        return render_template('reportes.html', user=user)

@app.route('/admin')
@admin_required
def admin():
    """Panel de administración del sistema"""
    try:
        user = obtener_usuario_por_id(session['user_id'])
        if not user:
            flash('Error al obtener información del usuario', 'danger')
            return redirect(url_for('login'))
        
        # Obtener datos para el panel de administración
        datos_admin = {
            'usuarios': listar_usuarios(),
            'roles': obtener_roles(),
            'permisos': obtener_permisos(),
            'configuracion': obtener_configuracion_sistema(),
            'logs_recientes': obtener_logs_sistema(limit=20)
        }
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'access_admin',
            'Acceso al panel de administración',
            request.remote_addr
        )
        
        return render_template('admin.html', 
                             user=user, 
                             datos=datos_admin)
        
    except Exception as e:
        logger.error(f"Error en panel de administración: {e}")
        flash('Error al cargar el panel de administración', 'danger')
        return render_template('admin.html', 
                             user={'username': session.get('username', 'Usuario')}, 
                             datos={})

#---------------------------------------------------------
# Rutas adicionales de administración
#---------------------------------------------------------

@app.route('/admin/roles/<int:role_id>/permisos', methods=['GET', 'POST'])
@admin_required
def gestionar_permisos_rol(role_id):
    """Gestiona permisos de un rol"""
    if request.method == 'GET':
        try:
            todos_permisos = obtener_permisos()
            permisos_rol = obtener_permisos_rol(role_id)
            
            return jsonify({
                'success': True,
                'todos_permisos': todos_permisos,
                'permisos_rol': [p['id'] for p in permisos_rol]
            })
        except Exception as e:
            logger.error(f"Error obteniendo permisos del rol: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            permission_ids = request.form.getlist('permissions')
            
            # Asignar permisos al rol
            exito = asignar_permisos_rol(role_id, permission_ids)
            
            if exito:
                registrar_actividad_usuario(
                    session['user_id'],
                    'update_role_permissions',
                    f'Permisos actualizados para rol {role_id}',
                    request.remote_addr
                )
                return jsonify({'success': True, 'message': 'Permisos actualizados correctamente'})
            else:
                return jsonify({'success': False, 'error': 'Error actualizando permisos'}), 500
                
        except Exception as e:
            logger.error(f"Error asignando permisos: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/usuarios/<int:user_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_usuario_admin(user_id):
    """Actualiza un usuario desde el panel de admin"""
    try:
        data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'role_id': request.form.get('role_id'),
            'is_active': request.form.get('is_active') == 'on'
        }
        
        exito = actualizar_usuario(user_id, data)
        
        if exito:
            registrar_actividad_usuario(
                session['user_id'],
                'update_user',
                f'Usuario {user_id} actualizado',
                request.remote_addr
            )
            return jsonify({'success': True, 'message': 'Usuario actualizado correctamente'})
        else:
            return jsonify({'success': False, 'error': 'Error actualizando usuario'}), 500
            
    except Exception as e:
        logger.error(f"Error actualizando usuario: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/usuarios/<int:user_id>/cambiar-password', methods=['POST'])
@admin_required
def cambiar_password_admin(user_id):
    """Cambia la contraseña de un usuario desde admin"""
    try:
        nueva_password = request.form.get('nueva_password')
        confirmar_password = request.form.get('confirmar_password')
        
        if nueva_password != confirmar_password:
            return jsonify({'success': False, 'error': 'Las contraseñas no coinciden'}), 400
        
        if len(nueva_password) < 6:
            return jsonify({'success': False, 'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Cambiar contraseña directamente (admin bypass)
        exito = cambiar_contrasena_usuario(user_id, None, nueva_password)
        if exito:
            registrar_actividad_usuario(
                session['user_id'],
                'admin_change_password',
                f'Contraseña cambiada para usuario {user_id}',
                request.remote_addr
            )
            return jsonify({'success': True, 'message': 'Contraseña actualizada correctamente'})
        else:
            return jsonify({'success': False, 'error': 'Error cambiando contraseña'}), 500
            
    except Exception as e:
        logger.error(f"Error cambiando contraseña: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

#---------------------------------------------------------
# Manejadores de errores
#---------------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Error 500: {str(e)}")
    return render_template('500.html'), 500

#---------------------------------------------------------
# Inicialización de la aplicación
#---------------------------------------------------------

def inicializar_sistema():
    """Inicializa el sistema con permisos y configuración básica"""
    try:
        logger.info("Inicializando sistema IDS...")
        inicializar_permisos_sistema()
        logger.info("Sistema IDS inicializado correctamente")
    except Exception as e:
        logger.error(f"Error inicializando sistema: {e}")

# Filtros personalizados para Jinja2
# Reemplazar TODOS los filtros existentes:

@app.template_filter('date_format')
def date_format(value, format='%Y-%m-%d %H:%M'):
    """Formatea fechas - VERSIÓN ROBUSTA"""
    try:
        if value is None:
            return "N/A"
        
        # Si es string, intentar parsearlo
        if isinstance(value, str):
            # Intentar varios formatos comunes
            formats_to_try = [
                '%Y-%m-%dT%H:%M:%S.%f%z',  # ISO con microsegundos y timezone
                '%Y-%m-%dT%H:%M:%S%z',     # ISO con timezone
                '%Y-%m-%dT%H:%M:%S.%f',    # ISO con microsegundos
                '%Y-%m-%dT%H:%M:%S',       # ISO básico
                '%Y-%m-%d %H:%M:%S.%f',    # Formato SQL con microsegundos
                '%Y-%m-%d %H:%M:%S',       # Formato SQL básico
                '%Y-%m-%d'                 # Solo fecha
            ]
            
            for fmt in formats_to_try:
                try:
                    if 'Z' in value:
                        value = value.replace('Z', '+00:00')
                    dt = datetime.datetime.strptime(value, fmt)
                    return dt.strftime(format)
                except ValueError:
                    continue
            
            # Si no se pudo parsear, devolver el string
            return str(value)
        
        # Si ya es un objeto datetime
        elif hasattr(value, 'strftime'):
            return value.strftime(format)
        
        # Para otros tipos
        else:
            return str(value) if value is not None else "N/A"
            
    except Exception as e:
        logger.error(f"Error formateando fecha {value}: {e}")
        return str(value) if value is not None else "N/A"

@app.template_filter('time_format')
def time_format(value):
    """Formatea solo la hora - VERSIÓN ROBUSTA"""
    try:
        if value is None:
            return "N/A"
        
        if isinstance(value, str):
            formats_to_try = [
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z', 
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in formats_to_try:
                try:
                    if 'Z' in value:
                        value = value.replace('Z', '+00:00')
                    dt = datetime.datetime.strptime(value, fmt)
                    return dt.strftime('%H:%M:%S')
                except ValueError:
                    continue
            
            return str(value)
        elif hasattr(value, 'strftime'):
            return value.strftime('%H:%M:%S')
        else:
            return str(value) if value is not None else "N/A"
    except Exception as e:
        logger.error(f"Error formateando hora {value}: {e}")
        return str(value) if value is not None else "N/A"

@app.template_filter('time_ago')
def time_ago(value):
    """Tiempo transcurrido - VERSIÓN ROBUSTA"""
    try:
        if value is None:
            return "Desconocido"
        
        if isinstance(value, str):
            formats_to_try = [
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            dt = None
            for fmt in formats_to_try:
                try:
                    if 'Z' in value:
                        value = value.replace('Z', '+00:00')
                    dt = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
            
            if dt is None:
                return "Desconocido"
                
        elif hasattr(value, 'replace'):
            dt = value
        else:
            return "Desconocido"
        
        now = datetime.now()
        
        # Manejar timezone si existe
        if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
            if now.tzinfo is None:
                from datetime import timezone
                now = now.replace(tzinfo=timezone.utc)
        elif now.tzinfo is not None and (not hasattr(dt, 'tzinfo') or dt.tzinfo is None):
            dt = dt.replace(tzinfo=now.tzinfo)
        
        try:
            diff = now - dt
        except TypeError:
            # Si hay problemas con timezone, usar versiones naive
            if hasattr(dt, 'replace') and hasattr(dt, 'tzinfo'):
                dt = dt.replace(tzinfo=None)
            now = datetime.now()
            diff = now - dt
        
        if diff.days > 0:
            return f"hace {diff.days} día{'s' if diff.days > 1 else ''}"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"hace {hours} hora{'s' if hours > 1 else ''}"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"hace {minutes} minuto{'s' if minutes > 1 else ''}"
        else:
            return "hace unos segundos"
            
    except Exception as e:
        logger.error(f"Error calculando tiempo transcurrido para {value}: {e}")
        return "Desconocido"

@app.template_filter('percentage')
def percentage_format(value):
    """Formatea porcentajes - VERSIÓN ROBUSTA"""
    try:
        if value is None:
            return "0%"
        
        if isinstance(value, str):
            try:
                value = float(value)
            except ValueError:
                return str(value) + "%"
        
        if isinstance(value, (int, float)):
            return "{:.1f}%".format(float(value))
        else:
            return str(value) + "%"
            
    except Exception as e:
        logger.error(f"Error formateando porcentaje {value}: {e}")
        return "0%"
    """Formatea números con separadores de miles"""
    try:
        if value is None:
            return "0"
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return str(value) if value is not None else "0"


@app.template_filter('date_format')
def date_format(value, format='%Y-%m-%d %H:%M'):
    """Formatea fechas"""
    try:
        if isinstance(value, str):
            # Intentar parsear fecha ISO
            from datetime import datetime
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime(format)
        elif hasattr(value, 'strftime'):
            return value.strftime(format)
        else:
            return str(value)
    except:
        return str(value) if value else ""

@app.template_filter('time_ago')
def time_ago(value):
    """Muestra tiempo transcurrido"""
    try:
        from datetime import datetime, timedelta
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        elif hasattr(value, 'replace'):
            dt = value
        else:
            return "Desconocido"
        
        now = datetime.now()
        if dt.tzinfo:
            now = now.replace(tzinfo=dt.tzinfo)
        
        diff = now - dt
        
        if diff.days > 0:
            return f"hace {diff.days} día{'s' if diff.days > 1 else ''}"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"hace {hours} hora{'s' if hours > 1 else ''}"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"hace {minutes} minuto{'s' if minutes > 1 else ''}"
        else:
            return "hace unos segundos"
    except:
        return "Desconocido"
# ========================================
# RUTAS API PARA CONTADORES DEL DASHBOARD
# ========================================
@app.route('/api/dashboard/clear-data', methods=['POST'])
@login_required
def clear_data():
    """Limpia todos los datos del sistema"""
    try:
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'}), 500

        with conn.cursor() as cursor:
            # Limpiar datos pero mantener estructura
            tables_to_clear = ['detections', 'user_activity']
            cleared_count = 0
            
            for table in tables_to_clear:
                try:
                    cursor.execute(f"DELETE FROM {table}")
                    cleared_count += cursor.rowcount
                except Exception as e:
                    logger.warning(f"No se pudo limpiar tabla {table}: {e}")
            
            conn.commit()

        conn.close()
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'clear_data',
            f'Datos del sistema limpiados ({cleared_count} registros)',
            request.remote_addr
        )
        
        logger.info(f"Datos limpiados por usuario {session['username']}")
        
        return jsonify({
            'success': True,
            'message': f'Datos limpiados exitosamente ({cleared_count} registros)',
            'cleared_records': cleared_count
        })

    except Exception as e:
        logger.error(f"Error limpiando datos: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/dashboard/status')
@login_required
def get_dashboard_status():
    """Obtiene el estado general del dashboard"""
    try:
        # Combinar estados del detector y federado
        detector_running = detector_process is not None and detector_process.poll() is None
        federado_running = federado_process is not None and federado_process.poll() is None
        
        status = {
            'detector': {
                'running': detector_running,
                'stats': detector_stats.copy()
            },
            'federado': {
                'running': federado_running,
                'stats': federado_stats.copy()
            },
            'system': {
                'timestamp': datetime.datetime.datetime.now().isoformat(),
                'uptime': time.time() - app_start_time if 'app_start_time' in globals() else 0
            }
        }
        
        return jsonify({'success': True, 'status': status})
        
    except Exception as e:
        logger.error(f"Error obteniendo estado del dashboard: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Variable para tracking de uptime de la aplicación
app_start_time = time.time()

@app.route('/api/dashboard/counters')
@login_required
def get_dashboard_counters():
    """Obtiene contadores combinando buffer temporal + BD"""
    try:
        # Obtener estadísticas del buffer (tiempo real)
        buffer_stats = stats_buffer.get_stats()
        
        # Contadores base desde BD
        conn = obtener_conexion()
        db_counters = {
            'total_detecciones': 0,
            'detecciones_24h': 0,
            'alertas_criticas': 0,
            'clientes_activos': 0,
            'total_clientes': 0
        }
        
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Total desde BD
                    cursor.execute("SELECT COUNT(*) FROM detections")
                    db_total = cursor.fetchone()[0] or 0
                    
                    # Últimas 24h desde BD
                    cursor.execute("""
                        SELECT COUNT(*) FROM detections 
                        WHERE timestamp >= NOW() - INTERVAL '24 hours'
                    """)
                    db_24h = cursor.fetchone()[0] or 0
                    
                    # Alertas críticas desde BD
                    cursor.execute("""
                        SELECT COUNT(*) FROM detections 
                        WHERE severity IN ('high', 'critical') 
                        AND timestamp >= NOW() - INTERVAL '24 hours'
                    """)
                    db_critical = cursor.fetchone()[0] or 0
                    
                    # Clientes desde BD
                    cursor.execute("SELECT COUNT(*) FROM federated_clients")
                    total_clients = cursor.fetchone()[0] or 0
                    
                    cursor.execute("""
                        SELECT COUNT(*) FROM federated_clients 
                        WHERE status = 'active' 
                        AND last_seen >= NOW() - INTERVAL '5 minutes'
                    """)
                    active_clients = cursor.fetchone()[0] or 0
                    
                    db_counters.update({
                        'total_detecciones': db_total,
                        'detecciones_24h': db_24h,
                        'alertas_criticas': db_critical,
                        'clientes_activos': active_clients,
                        'total_clientes': total_clients
                    })
                    
            except Exception as e:
                logger.error(f"Error consultando BD para contadores: {e}")
            finally:
                conn.close()
        
        # Combinar estadísticas BD + buffer temporal
        combined_counters = {
            'total_detecciones': db_counters['total_detecciones'] + buffer_stats['total_detections'],
            'detecciones_24h': db_counters['detecciones_24h'] + buffer_stats['total_detections'],  # Buffer es reciente
            'alertas_criticas': db_counters['alertas_criticas'] + buffer_stats['detections_by_severity'].get('critical', 0) + buffer_stats['detections_by_severity'].get('high', 0),
            'clientes_activos': max(db_counters['clientes_activos'], 1 if detector_process and detector_process.poll() is None else 0),
            'total_clientes': max(db_counters['total_clientes'], 1 if detector_process and detector_process.poll() is None else 0),
            'clientes_conectados': db_counters['clientes_activos']
        }
        
        # Información adicional del sistema
        buffer_info = detection_buffer.get_stats()
        
        return jsonify({
            'success': True,
            'counters': combined_counters,
            'timestamp': datetime.datetime.datetime.now().isoformat(),
            'source': 'combined',
            'buffer_info': {
                'detections_pending': buffer_info['buffer_size'],
                'save_rate': f"{buffer_info['save_rate']:.1f}%",
                'total_processed': buffer_info['total_buffered']
            },
            'real_time_stats': {
                'uptime': f"{buffer_stats['uptime_seconds']:.0f}s",
                'recent_activity': len(buffer_stats['recent_detections']),
                'types_detected': len(buffer_stats['detections_by_type'])
            }
        })

    except Exception as e:
        logger.error(f"Error obteniendo contadores combinados: {e}")
        return jsonify({
            'success': False, 
            'error': str(e),
            'counters': {
                'total_detecciones': 0,
                'detecciones_24h': 0,
                'alertas_criticas': 0,
                'clientes_activos': 0,
                'total_clientes': 0,
                'clientes_conectados': 0
            }
        }), 500
    
@app.route('/api/dashboard/recent-detections')
@login_required
def get_recent_detections():
    """Obtiene detecciones recientes con manejo de errores corregido"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'detections': [], 'error': 'Sin conexión BD'})
        
        try:
            # Usar cursor normal en lugar de RealDictCursor para evitar problemas
            with conn.cursor() as cur:
                cur.execute("""
                SELECT 
                    d.id,
                    d.detection_id,
                    d.anomaly_type,
                    d.severity,
                    d.confidence_score,
                    d.source_ip,
                    d.destination_ip,
                    d.source_port,
                    d.destination_port,
                    d.protocol,
                    d.timestamp,
                    d.created_at,
                    d.is_confirmed,
                    d.false_positive,
                    COALESCE(fc.name, fc.client_id, 'Cliente-' || d.client_id::text) as client_name
                FROM detections d
                LEFT JOIN federated_clients fc ON d.client_id = fc.id
                ORDER BY d.created_at DESC
                LIMIT %s
                """, (limit,))
                
                rows = cur.fetchall()
                
                # Construir manualmente los diccionarios
                detections = []
                for row in rows:
                    detection = {
                        'id': row[0],
                        'detection_id': row[1] or '',
                        'anomaly_type': row[2] or 'Unknown',
                        'severity': row[3] or 'medium',
                        'confidence_score': float(row[4]) if row[4] is not None else 0.0,
                        'source_ip': row[5] or '0.0.0.0',
                        'destination_ip': row[6] or '0.0.0.0',
                        'source_port': row[7] or 0,
                        'destination_port': row[8] or 0,
                        'protocol': row[9] or 'TCP',
                        'timestamp': row[10].isoformat() if row[10] else '',
                        'created_at': row[11].isoformat() if row[11] else '',
                        'is_confirmed': bool(row[12]) if row[12] is not None else False,
                        'false_positive': bool(row[13]) if row[13] is not None else False,
                        'client_name': row[14] or 'Desconocido'
                    }
                    detections.append(detection)
                
                logger.info(f"✅ Detecciones recientes obtenidas: {len(detections)}")
                
                return jsonify({
                    'success': True,
                    'detections': detections,
                    'total': len(detections)
                })
                
        except Exception as e:
            logger.error(f"Error en query detecciones: {e}")
            return jsonify({'detections': [], 'error': str(e)})
            
    except Exception as e:
        logger.error(f"Error general en detecciones: {e}")
        return jsonify({'detections': [], 'error': str(e)})
        
    finally:
        if conn:
            conn.close()
# AGREGAR después de las otras rutas API:

# ENCONTRAR LA FUNCIÓN EXISTENTE add_detection_to_buffer Y REEMPLAZARLA CON:

@app.route('/api/buffer/add-detection', methods=['POST'])
def add_detection_to_buffer():
    """Recibe detecciones del detector_integrado y las guarda directamente"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        detection = data.get('detection')
        
        if not user_id or not detection:
            return jsonify({'success': False, 'error': 'Datos incompletos'}), 400
        
        # Preparar datos para inserción directa
        detection_data = {
            'user_id': user_id,
            'detection_id': detection.get('detection_id', str(uuid.uuid4())),
            'timestamp': detection.get('timestamp'),
            'anomaly_type': detection.get('anomaly_type'),
            'severity': normalizar_severity(detection.get('severity')),
            'confidence_score': detection.get('confidence_score', 0.0),
            'source_ip': detection.get('source_ip'),
            'destination_ip': detection.get('destination_ip'),
            'source_port': detection.get('source_port'),
            'destination_port': detection.get('destination_port'),
            'protocol': detection.get('protocol'),
            'raw_output': detection.get('raw_output'),
            'raw_data': detection.get('raw_data', {})
        }
        
        # ✅ GUARDAR DIRECTAMENTE EN POSTGRESQL:
        success = save_detection_to_database(detection_data)
        
        # ✅ ACTUALIZAR STATS PARA DASHBOARD:
        if 'stats_buffer' in globals():
            stats_buffer.add_detection(detection_data)
        
        if success:
            logger.info(f"✅ Detección guardada | Usuario: {user_id} | Tipo: {detection_data.get('anomaly_type')}")
            return jsonify({'success': True, 'message': 'Detección guardada exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error guardando en BD'}), 500
        
    except Exception as e:
        logger.error(f"❌ Error procesando detección: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def save_detection_to_database(detection_data):
    """Guarda detección directamente en PostgreSQL"""
    try:
        conn = obtener_conexion()
        if not conn:
            return False
        
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO detections (
                    detection_id, client_id, model_id, timestamp, source_ip, destination_ip,
                    source_port, destination_port, protocol, anomaly_type,
                    severity, confidence_score, raw_data, is_confirmed, false_positive
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                detection_data.get('detection_id'),
                1,  # client_id default
                1,  # model_id default
                detection_data.get('timestamp', datetime.datetime.now()),
                detection_data.get('source_ip', '0.0.0.0'),
                detection_data.get('destination_ip', '0.0.0.0'),
                detection_data.get('source_port', 0),
                detection_data.get('destination_port', 0),
                detection_data.get('protocol', 'TCP'),
                detection_data.get('anomaly_type', 'Unknown'),
                detection_data.get('severity', 'medium'),
                detection_data.get('confidence_score', 0.5),
                json.dumps(detection_data.get('raw_data', {})),
                False,
                False
            ))
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Error guardando detección en BD: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False
@app.route('/api/buffer/status')
@login_required
def get_buffer_status():
    """Obtiene estado detallado del sistema de buffer"""
    try:
        buffer_stats = detection_buffer.get_stats()
        realtime_stats = stats_buffer.get_stats()
        
        return jsonify({
            'success': True,
            'buffer_stats': buffer_stats,
            'realtime_stats': realtime_stats,
            'system_status': {
                'detector_running': detector_process is not None and detector_process.poll() is None,
                'federado_running': federado_process is not None and federado_process.poll() is None,
                'database_connected': obtener_conexion() is not None,
                'buffer_health': 'healthy' if buffer_stats['buffer_size'] < 800 else 'warning'
            },
            'timestamp': datetime.datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo estado del buffer: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# AGREGAR ESTAS FUNCIONES después de marcar_enviado_respaldo:

def enviar_actualizacion_modelo(self, model_weights, performance_metrics):
    """Envía actualización del modelo para aprendizaje federado"""
    try:
        url = f"{self.flask_api_url}/api/federated/model-update"
        
        payload = {
            'client_id': int(self.client_id),
            'user_id': self.user_id,
            'model_weights': model_weights,  # Serializado
            'performance_metrics': performance_metrics,
            'training_samples': self.stats['total_packets'],
            'timestamp': datetime.datetime.now().isoformat(),
            'device_info': {
                'type': self.computing_device_info.get('type'),
                'model': self.computing_device_info.get('model'),
                'serial': self.computing_device_info.get('serial_number')
            }
        }
        
        response = requests.post(
            url,
            json=payload,
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                self.model_updates_sent += 1
                print(f"📤 [FEDERADO] Actualización de modelo enviada #{self.model_updates_sent}")
                return True
        
        print(f"⚠️ [FEDERADO] Error enviando actualización: HTTP {response.status_code}")
        return False
        
    except Exception as e:
        print(f"⚠️ [FEDERADO] Error: {e}")
        return False

def recibir_modelo_global(self):
    """Recibe el modelo global actualizado del servidor federado"""
    try:
        url = f"{self.flask_api_url}/api/federado/global-model"
        
        params = {
            'client_id': self.client_id,
            'user_id': self.user_id
        }
        
        response = requests.get(url, params=params, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                model_data = result.get('model_data')
                self.model_updates_received += 1
                print(f"📥 [FEDERADO] Modelo global recibido #{self.model_updates_received}")
                return model_data
        
        return None
        
    except Exception as e:
        print(f"⚠️ [FEDERADO] Error recibiendo modelo: {e}")
        return None

def verificar_conectividad_federado(self):
    """Verifica conectividad con el servidor federado"""
    try:
        url = f"{self.flask_api_url}/health-extended"
        
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            federated_available = result.get('federated_learning', {}).get('enabled', False)
            
            if federated_available:
                print("✅ [FEDERADO] Servidor federado disponible")
                return True
            else:
                print("⚠️ [FEDERADO] Servidor disponible pero aprendizaje federado desactivado")
                return False
        else:
            print(f"⚠️ [FEDERADO] Servidor no disponible: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ [FEDERADO] Error verificando conectividad: {e}")
        return False


if __name__ == "__main__":
    inicializar_sistema()
    
    print("=" * 60)
    print("🛡️  SISTEMA IDS FEDERADO - SERVIDOR WEB")
    print("=" * 60)
    print("🌐 Dashboard: http://localhost:5000")
    print("👤 Usuario por defecto: admin")
    print("🔑 Contraseña por defecto: admin123")
    print()
    print("📋 Funcionalidades disponibles:")
    print("   • Dashboard en tiempo real")
    print("   • Control de detector de flujos")
    print("   • Control de sistema federado")
    print("   • Gestión de detecciones")
    print("   • Reportes y estadísticas")
    print("   • Administración de usuarios")
    print()
    print("🔧 Para controlar detector/federado:")
    print("   Usar los botones en el dashboard web")
    print("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )