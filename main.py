#REVISADO 16.07.25 
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_from_directory
from functools import wraps
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor
from collections import deque
import datetime
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
try:
    from enviar_correo import enviarcorreoalerta
    CORREO_DISPONIBLE = True
    print("📧 Sistema de correo cargado correctamente")
except ImportError:
    CORREO_DISPONIBLE = False
    print("⚠️ Sistema de correo no disponible")
    
    # Función dummy si no está disponible
    def enviarcorreoalerta():
        print("📧 Sistema de correo no configurado")
        return False
if sys.platform == 'win32':
    # Configurar UTF-8 para Windows
    import locale
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    if sys.stderr.encoding != 'utf-8':
        sys.stderr.reconfigure(encoding='utf-8')
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
# AGREGAR estas definiciones globales después de línea 105:
federado_stats = {
    'status': 'stopped',
    'host': '0.0.0.0',
    'port': 8765,
    'server': 'ws://localhost:8765',
    'clients': 0,
    'uptime': 0
}

# Variables globales para salida del detector
detector_output_queue = []
detector_output_lock = threading.Lock() 
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
        }
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
            detection['display_time'] = datetime.datetime.now().isoformat()
            self.stats['recent_detections'].appendleft(detection)
            
            # Estadísticas por hora
            current_hour = datetime.datetime.now().hour
            if current_hour not in self.stats['hourly_stats']:
                self.stats['hourly_stats'][current_hour] = 0
            current_hour = datetime.datetime.now().hour
    
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
            'timestamp': datetime.datetime.now().isoformat(),
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
            'timestamp': datetime.datetime.now().isoformat(),
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
                    if len(detector_output_queue) > 200:
                        detector_output_queue.pop(0)
                logger.info(f"[DETECTOR] {line}")
                
    except Exception as e:
        logger.error(f"Error capturando salida del detector: {e}")
    finally:
        logger.info("Captura de salida del detector terminada")

@app.route('/api/detector/start', methods=['POST'])
@login_required
def start_detector():
    """Inicia el detector integrado federado"""
    global detector_process, detector_output_queue
    
    try:
        data = request.get_json() or {}
        
        #   OBTENER PARÁMETROS DINÁMICOS DEL FRONTEND
        user_id = session.get('user_id', 1)  # ← DESDE SESIÓN
        interface = data.get('interface', 'Wi-Fi')  # ← DESDE SELECTOR
        servidor_federado = data.get('servidor_federado', 'ws://192.168.18.88:8765')  # ← DESDE INPUT
        
        if detector_process and detector_process.poll() is None:
            return jsonify({'error': 'El detector ya está ejecutándose'}), 400
        detector_output_queue.clear()
        # Verificar archivos necesarios
        if not os.path.exists('detector_integrado.py'):
            return jsonify({'error': 'detector_integrado.py no encontrado'}), 500
        
        #   BUSCAR MODELO DINÁMICAMENTE (COMO YA LO TIENES)
        model_path = 'model/modelo_rf.pkl'
        if not os.path.exists(model_path):
            model_path = 'model/modelo_rf_optimizado.pkl'
        if not os.path.exists(model_path):
            return jsonify({'error': 'Modelo no encontrado'}), 500
        
        #   COMANDO CON PARÁMETROS DINÁMICOS
        cmd = [
            sys.executable, 'detector_integrado.py',
            '--user-id', str(user_id),                    # ← DESDE SESIÓN
            '--interface', interface,                      # ← DESDE SELECTOR HTML
            '--model', model_path,                        # ← DINÁMICO
            '--flask-url', 'http://localhost:5000',       # ← FIJO
            '--servidor-federado', servidor_federado      # ← DESDE INPUT HTML
        ]
        
        # MENSAJE EN CONSOLA CON PARÁMETROS REALES
        print(f"\n{'='*80}")
        print("INICIANDO DETECTOR INTEGRADO FEDERADO")
        print(f"{'='*80}")
        print(f"Usuario ID (sesión): {user_id}")
        print(f"Interfaz (selector): {interface}")
        print(f"Modelo (dinámico): {model_path}")
        print(f"Flask URL (fijo): http://localhost:5000")
        print(f"Servidor Federado (input): {servidor_federado}")
        print(f"Comando: {' '.join(cmd)}")
        print(f"{'='*80}")

        # EJECUTAR CON PARÁMETROS DINÁMICOS
        detector_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=os.getcwd()
        )
        
        def capture_detector_output_improved():
            """Captura la salida del detector sin bloquear"""
            global detector_output_queue
            
            try:
                while detector_process and detector_process.poll() is None:
                    try:
                        # Leer línea con timeout corto
                        line = detector_process.stdout.readline()
                        
                        if line:
                            line_clean = line.rstrip()
                            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                            
                            # ✅ CLASIFICAR TIPO DE MENSAJE
                            message_type = 'info'
                            line_upper = line_clean.upper()
                            
                            if any(keyword in line_upper for keyword in ['ERROR', 'FAILED', 'EXCEPTION']):
                                message_type = 'error'
                            elif any(keyword in line_upper for keyword in ['WARNING', 'WARN']):
                                message_type = 'warning'
                            elif any(keyword in line_upper for keyword in ['ATTACK', 'SUSPICIOUS', 'SOSPECHOSO']):
                                message_type = 'alert'
                            elif any(keyword in line_upper for keyword in ['SUCCESS', 'CONECTADO', 'INICIADO']):
                                message_type = 'success'
                            elif any(keyword in line_upper for keyword in ['NORMAL', 'INFO']):
                                message_type = 'normal'
                            elif 'FL-' in line_upper:
                                message_type = 'federado'
                            
                            # ✅ AGREGAR A COLA CON LÍMITE
                            processed_line = {
                                'timestamp': timestamp,
                                'raw': line_clean,
                                'type': message_type,
                                'component': 'DETECTOR'
                            }
                            
                            detector_output_queue.append(processed_line)
                            
                            # ✅ MANTENER SOLO ÚLTIMAS 500 LÍNEAS
                            if len(detector_output_queue) > 500:
                                detector_output_queue.pop(0)
                            
                            # ✅ LOG SELECTIVO - SOLO IMPORTANTES
                            if message_type in ['error', 'warning', 'alert', 'success']:
                                logger.info(f"[DETECTOR-{message_type.upper()}] {line_clean}")
                            elif 'Total :' in line_clean:  # Contadores importantes
                                logger.info(f"[DETECTOR-COUNT] {line_clean}")
                        
                        else:
                            # Sin línea, pequeña pausa para no consumir CPU
                            time.sleep(0.1)
                            
                    except Exception as e:
                        logger.error(f"Error leyendo línea del detector: {e}")
                        time.sleep(0.5)
                        
            except Exception as e:
                logger.error(f"Error en captura de salida del detector: {e}")
            finally:
                logger.info("🔚 Captura de salida del detector finalizada")
        
        # Captura de salida
        
        threading.Thread(target=capture_detector_output_improved, daemon=True).start()
        
        print(f"✅ Detector iniciado con PID: {detector_process.pid}")
        print(f"📊 Salida capturada en API /api/detector/output")
        print(f"{'='*80}\n")
        
        # Actualizar estadísticas
        detector_stats.update({
            'status': 'running',
            'interface': interface,
            'user_id': user_id,
            'servidor_federado': servidor_federado,
            'model_path': model_path,
            'start_time': time.time(),
            'pid': detector_process.pid
        })
        
        return jsonify({
            'success': True,
            'message': f'Detector iniciado correctamente',
            'pid': detector_process.pid,
            'output_available': True,
            'config': {
                'user_id': user_id,
                'interface': interface,
                'model_path': model_path,
                'flask_url': 'http://localhost:5000',
                'servidor_federado': servidor_federado
            }
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
    global detector_output_queue
    
    try:
        # Parámetros de consulta
        since = request.args.get('since', 0, type=int)
        filter_type = request.args.get('filter', 'all')  # all, errors, alerts, federado, normal
        limit = request.args.get('limit', 100, type=int)
        
        # ✅ OBTENER LÍNEAS DESDE ÍNDICE
        available_lines = detector_output_queue[since:] if since < len(detector_output_queue) else []
        
        # ✅ APLICAR FILTROS
        if filter_type != 'all':
            if filter_type == 'errors':
                available_lines = [line for line in available_lines if line['type'] in ['error', 'warning']]
            elif filter_type == 'alerts':
                available_lines = [line for line in available_lines if line['type'] == 'alert']
            elif filter_type == 'federado':
                available_lines = [line for line in available_lines if line['type'] == 'federado' or 'FL-' in line['raw']]
            elif filter_type == 'normal':
                available_lines = [line for line in available_lines if line['type'] == 'normal']
            elif filter_type == 'important':
                available_lines = [line for line in available_lines if line['type'] in ['error', 'warning', 'alert', 'success']]
        
        # ✅ LIMITAR RESULTADO
        if len(available_lines) > limit:
            available_lines = available_lines[-limit:]
        
        # Verificar si el proceso sigue corriendo
        is_running = detector_process is not None and detector_process.poll() is None
        
        return jsonify({
            'success': True,
            'lines': available_lines,
            'total_available': len(detector_output_queue),
            'filtered_count': len(available_lines),
            'since': since,
            'filter_applied': filter_type,
            'running': is_running,
            'timestamp': datetime.datetime.now().isoformat(),
            'stats': {
                'total_lines': len(detector_output_queue),
                'errors': len([l for l in detector_output_queue if l['type'] == 'error']),
                'warnings': len([l for l in detector_output_queue if l['type'] == 'warning']),
                'alerts': len([l for l in detector_output_queue if l['type'] == 'alert']),
                'federado_msgs': len([l for l in detector_output_queue if l['type'] == 'federado'])
            }
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo salida del detector: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'lines': [],
            'running': detector_process is not None and detector_process.poll() is None
        }), 500

# AGREGAR DESPUÉS de get_detector_output:

@app.route('/api/detector/clear-output', methods=['POST'])
@login_required
def clear_detector_output():
    """Limpia la cola de salida del detector"""
    global detector_output_queue
    
    try:
        lines_cleared = len(detector_output_queue)
        detector_output_queue.clear()
        
        logger.info(f"Salida del detector limpiada: {lines_cleared} líneas eliminadas")
        
        return jsonify({
            'success': True,
            'message': f'Salida limpiada: {lines_cleared} líneas eliminadas',
            'lines_cleared': lines_cleared
        })
        
    except Exception as e:
        logger.error(f"Error limpiando salida del detector: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
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
            'timestamp': datetime.datetime.now().isoformat()
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
            'last_updated': datetime.datetime.now().isoformat(),
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
            'download_timestamp': datetime.datetime.now().isoformat()
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
                            'timestamp': datetime.datetime.now().isoformat(),
                            'component': 'Sistema',
                            'level': 'INFO',
                            'message': line.strip()
                        })
        
        # Si no hay logs, agregar datos de ejemplo
        if not log_entries:
            log_entries = [
                {
                    'timestamp': datetime.datetime.now().isoformat(),
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
            'timestamp': datetime.datetime.now().isoformat()
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
            'timestamp': datetime.datetime.now().isoformat()
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
            'timestamp': datetime.datetime.now().isoformat()
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
                'timestamp': datetime.datetime.now().isoformat(),
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
@login_required
def admin():
    """Panel de administración unificado"""
    try:
        # Verificar si es admin
        if session.get('role') != 'admin':
            flash('Acceso denegado. Se requieren permisos de administrador.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Obtener usuarios para la tabla
        usuarios = listar_usuarios_basico()
        
        logger.info(f"🔧 Admin {session.get('username')} accedió al panel de configuración")
        
        return render_template('admin.html', 
                             user={'username': session.get('username', 'Admin')},
                             usuarios=usuarios)
        
    except Exception as e:
        logger.error(f"❌ Error en panel admin: {e}")
        flash('Error al cargar el panel de administración', 'danger')
        return redirect(url_for('dashboard'))
    
def guardar_configuracion_federado(data):
    """Guarda configuración del servidor federado"""
    try:
        global federado_stats
        
        config = {
            'servidor_host': data.get('servidor_host', '0.0.0.0'),
            'servidor_puerto': int(data.get('servidor_puerto', 8765)),
            'max_clientes': int(data.get('max_clientes', 10)),
            'rondas_agregacion': int(data.get('rondas_agregacion', 10)),
            'min_clientes_ronda': int(data.get('min_clientes_ronda', 3)),
            'timeout_cliente': int(data.get('timeout_cliente', 30))
        }
        
        # ✅ VALIDACIONES
        if not (1024 <= config['servidor_puerto'] <= 65535):
            return jsonify({'success': False, 'error': 'Puerto debe estar entre 1024 y 65535'})
        
        if config['max_clientes'] < 1 or config['max_clientes'] > 50:
            return jsonify({'success': False, 'error': 'Máximo de clientes debe estar entre 1 y 50'})
        
        # ✅ ACTUALIZAR STATS GLOBALES
        federado_stats.update({
            'host': config['servidor_host'],
            'port': config['servidor_puerto'],
            'server': f"ws://{config['servidor_host']}:{config['servidor_puerto']}",
            'max_clients': config['max_clientes']
        })
        
        # ✅ GUARDAR EN BD
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                # Insertar configuración federada individualmente
                federado_config_map = {
                    'federado_host': config['servidor_host'],
                    'federado_puerto': str(config['servidor_puerto']),
                    'federado_max_clientes': str(config['max_clientes']),
                    'federado_rondas': str(config['rondas_agregacion']),
                    'federado_min_clientes': str(config['min_clientes_ronda']),
                    'federado_timeout': str(config['timeout_cliente'])
                }
                
                for key, value in federado_config_map.items():
                    try:
                        cursor.execute("""
                            INSERT INTO system_config (config_key, config_value, data_type, updated_at)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (config_key) 
                            DO UPDATE SET 
                                config_value = EXCLUDED.config_value,
                                updated_at = CURRENT_TIMESTAMP
                        """, (key, value, 'string'))
                        
                    except Exception as e:
                        logger.error(f"Error insertando {key}: {e}")
                        continue
                
                conn.commit()
            conn.close()
        
        # ✅ REGISTRAR ACTIVIDAD
        registrar_actividad_usuario(
            session['user_id'],
            'update_config_federado',
            f'Configuración federada actualizada: {config["servidor_host"]}:{config["servidor_puerto"]}',
            request.remote_addr
        )
        
        logger.info(f"✅ Configuración federada guardada: {config}")
        
        return jsonify({
            'success': True,
            'message': 'Configuración federada guardada correctamente',
            'config': config,
            'restart_required': federado_process and federado_process.poll() is None
        })
        
    except Exception as e:
        logger.error(f"❌ Error guardando config federada: {e}")
        return jsonify({'success': False, 'error': str(e)})

def guardar_configuracion_seguridad(data):
    """Guarda configuración de seguridad"""
    try:
        config = {
            'tiempo_sesion': int(data.get('tiempo_sesion', 8)),
            'max_intentos_login': int(data.get('max_intentos_login', 5)),
            'forzar_ssl': data.get('forzar_ssl') == 'on',
            'habilitar_api': data.get('habilitar_api') == 'on',
            'token_expiracion': int(data.get('token_expiracion', 2)),
            'rate_limit': int(data.get('rate_limit', 100))
        }
        
        # ✅ VALIDACIONES
        if not (1 <= config['tiempo_sesion'] <= 24):
            return jsonify({'success': False, 'error': 'Tiempo de sesión debe estar entre 1 y 24 horas'})
        
        if not (3 <= config['max_intentos_login'] <= 10):
            return jsonify({'success': False, 'error': 'Intentos de login deben estar entre 3 y 10'})
        
        # ✅ APLICAR CONFIGURACIÓN INMEDIATAMENTE
        if config['tiempo_sesion'] != 8:  # Si cambió el tiempo de sesión
            app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=config['tiempo_sesion'])
        
        if config['token_expiracion'] != 2:  # Si cambió la expiración del token
            app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=config['token_expiracion'])
        
        # ✅ GUARDAR EN BD
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                # Insertar configuración de seguridad individualmente
                seguridad_config_map = {
                    'seguridad_tiempo_sesion': str(config['tiempo_sesion']),
                    'seguridad_max_intentos': str(config['max_intentos_login']),
                    'seguridad_ssl': str(config['forzar_ssl']).lower(),
                    'seguridad_api': str(config['habilitar_api']).lower(),
                    'seguridad_token_exp': str(config['token_expiracion']),
                    'seguridad_rate_limit': str(config['rate_limit'])
                }
                
                for key, value in seguridad_config_map.items():
                    try:
                        cursor.execute("""
                            INSERT INTO system_config (config_key, config_value, data_type, updated_at)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (config_key) 
                            DO UPDATE SET 
                                config_value = EXCLUDED.config_value,
                                updated_at = CURRENT_TIMESTAMP
                        """, (key, value, 'string'))
                        
                    except Exception as e:
                        logger.error(f"Error insertando {key}: {e}")
                        continue
                
                conn.commit()
            conn.close()
        
        # ✅ REGISTRAR ACTIVIDAD
        registrar_actividad_usuario(
            session['user_id'],
            'update_config_seguridad',
            f'Configuración de seguridad actualizada: sesión {config["tiempo_sesion"]}h',
            request.remote_addr
        )
        
        logger.info(f"✅ Configuración de seguridad guardada: {config}")
        
        return jsonify({
            'success': True,
            'message': 'Configuración de seguridad guardada correctamente',
            'config': config,
            'applied_immediately': True
        })
        
    except Exception as e:
        logger.error(f"❌ Error guardando config seguridad: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/admin/configuracion/<tipo>', methods=['GET'])
@login_required
def cargar_configuracion(tipo):
    """Carga configuración actual del sistema"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'})
        
        with conn.cursor() as cursor:
            if tipo == 'general':
                # Cargar configuración general
                keys = ['sistema_nombre', 'max_detecciones_dia', 'umbral_confianza', 
                       'alertas_email', 'email_admin', 'intervalo_reportes']
                
            elif tipo == 'federado':
                # Cargar configuración federada
                keys = ['federado_host', 'federado_puerto', 'federado_max_clientes',
                       'federado_rondas', 'federado_min_clientes', 'federado_timeout']
                
            elif tipo == 'seguridad':
                # Cargar configuración de seguridad
                keys = ['seguridad_tiempo_sesion', 'seguridad_max_intentos', 'seguridad_ssl',
                       'seguridad_api', 'seguridad_token_exp', 'seguridad_rate_limit']
            else:
                return jsonify({'success': False, 'error': 'Tipo no válido'})
            
            # Obtener valores de configuración
            config = {}
            for key in keys:
                try:
                    cursor.execute("""
                        SELECT config_value FROM system_config WHERE config_key = %s
                    """, (key,))
                    result = cursor.fetchone()
                    config[key] = result[0] if result else None
                except Exception as e:
                    logger.error(f"Error cargando {key}: {e}")
                    config[key] = None
        
        conn.close()
        
        # Devolver configuración con valores por defecto si no existen
        defaults = {
            'general': {
                'sistema_nombre': 'IDS Federado v1.0',
                'max_detecciones_dia': '10000',
                'umbral_confianza': '75',
                'alertas_email': 'on',
                'email_admin': 'admin@empresa.com',
                'intervalo_reportes': '6'
            },
            'federado': {
                'federado_host': '0.0.0.0',
                'federado_puerto': '8765',
                'federado_max_clientes': '10',
                'federado_rondas': '10',
                'federado_min_clientes': '3',
                'federado_timeout': '30'
            },
            'seguridad': {
                'seguridad_tiempo_sesion': '8',
                'seguridad_max_intentos': '5',
                'seguridad_ssl': 'off',
                'seguridad_api': 'on',
                'seguridad_token_exp': '2',
                'seguridad_rate_limit': '100'
            }
        }
        
        # Aplicar valores por defecto para campos vacíos
        for key in config:
            if config[key] is None:
                config[key] = defaults[tipo].get(key, '')
        
        return jsonify({
            'success': True,
            'config': config,
            'tipo': tipo
        })
        
    except Exception as e:
        logger.error(f"❌ Error cargando configuración {tipo}: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/admin/configuracion/<tipo>', methods=['POST'])
@login_required  
def guardar_configuracion(tipo):
    """Guardar configuración del sistema - FUNCIONAL"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        data = request.form.to_dict()
        logger.info(f"💾 Guardando configuración {tipo}: {data}")
        
        # ✅ PROCESAR SEGÚN EL TIPO DE CONFIGURACIÓN
        if tipo == 'general':
            return guardar_configuracion_general(data)
        elif tipo == 'federado':
            return guardar_configuracion_federado(data)
        elif tipo == 'seguridad':
            return guardar_configuracion_seguridad(data)
        else:
            return jsonify({'success': False, 'error': f'Tipo de configuración no válido: {tipo}'})
        
    except Exception as e:
        logger.error(f"❌ Error guardando configuración {tipo}: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/admin/usuarios/crear', methods=['POST'])
@login_required
def crear_usuario_admin():
    """Crear nuevo usuario desde panel admin - CORREGIDO"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        # ✅ OBTENER Y VALIDAR DATOS
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        role = request.form.get('role', 'user')
        is_active = request.form.get('is_active') == 'on'
        
        # ✅ VALIDACIONES
        if not username or len(username) < 3:
            return jsonify({'success': False, 'error': 'El nombre de usuario debe tener al menos 3 caracteres'})
        
        if not email or '@' not in email:
            return jsonify({'success': False, 'error': 'Email inválido'})
        
        if not password or len(password) < 6:
            return jsonify({'success': False, 'error': 'La contraseña debe tener al menos 6 caracteres'})
        
        if role not in ['admin', 'user', 'viewer']:
            return jsonify({'success': False, 'error': 'Rol inválido'})
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'})
        
        try:
            with conn.cursor() as cursor:
                # Verificar duplicados
                cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
                if cursor.fetchone():
                    return jsonify({'success': False, 'error': 'El usuario o email ya existe'})
                
                # ✅ OBTENER ROLE_ID DESDE TABLA ROLES
                cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
                role_result = cursor.fetchone()
                
                if not role_result:
                    # Si no existe el rol, crearlo
                    cursor.execute("""
                        INSERT INTO roles (name, display_name, description) 
                        VALUES (%s, %s, %s) 
                        ON CONFLICT (name) DO NOTHING
                        RETURNING id
                    """, (role, role.title(), f"Rol {role}"))
                    
                    role_result = cursor.fetchone()
                    if not role_result:
                        # Si sigue sin existir, obtener el ID existente
                        cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
                        role_result = cursor.fetchone()
                
                role_id = role_result[0]
                
                # ✅ CREAR USUARIO CON ROLE_ID
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, first_name, last_name, role_id, is_active, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING id
                """, (username, email, password_hash, first_name, last_name, role_id, is_active))
                
                user_id = cursor.fetchone()[0]
                conn.commit()
                
                # ✅ REGISTRAR ACTIVIDAD
                registrar_actividad_usuario(
                    session['user_id'],
                    'create_user',
                    f'Usuario creado: {username} ({role})',
                    request.remote_addr
                )
                
                logger.info(f"✅ Usuario creado: {username} (ID: {user_id}, Role ID: {role_id})")
                
                return jsonify({
                    'success': True,
                    'message': f'Usuario {username} creado correctamente',
                    'user_id': user_id,
                    'username': username,
                    'role': role
                })
                
        except Exception as e:
            conn.rollback()
            logger.error(f"❌ Error creando usuario: {e}")
            return jsonify({'success': False, 'error': str(e)})
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"❌ Error en crear usuario admin: {e}")
        return jsonify({'success': False, 'error': str(e)})
def guardar_configuracion_general(data):
    """Guarda configuración general del sistema"""
    try:
        # ✅ VALIDAR Y PROCESAR DATOS
        config = {
            'sistema_nombre': data.get('sistema_nombre', 'IDS Federado v1.0'),
            'max_detecciones_dia': int(data.get('max_detecciones_dia', 10000)),
            'umbral_confianza': float(data.get('umbral_confianza', 75)) / 100,
            'alertas_email': data.get('alertas_email') == 'on',
            'email_admin': data.get('email_admin', 'admin@empresa.com'),
            'intervalo_reportes': int(data.get('intervalo_reportes', 6))
        }
        
        logger.info(f"✅ Configuración procesada: {config}")
        
        # ✅ GUARDAR EN BASE DE DATOS CON ESTRUCTURA CORRECTA
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                # Verificar si la tabla existe con la estructura correcta
                cursor.execute("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name = 'system_config'
                """)
                columns = [row[0] for row in cursor.fetchall()]
                logger.info(f"🔍 Columnas existentes en system_config: {columns}")
                
                # ✅ INSERTAR CONFIGURACIÓN INDIVIDUALMENTE POR CONFIG_KEY
                for key, value in config.items():
                    try:
                        cursor.execute("""
                            INSERT INTO system_config (config_key, config_value, data_type, updated_at)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                            ON CONFLICT (config_key) 
                            DO UPDATE SET 
                                config_value = EXCLUDED.config_value,
                                updated_at = CURRENT_TIMESTAMP
                        """, (key, str(value), 'string'))
                        
                    except Exception as e:
                        logger.error(f"Error insertando {key}: {e}")
                        continue
                
                conn.commit()
            conn.close()
        
        # ✅ REGISTRAR ACTIVIDAD
        registrar_actividad_usuario(
            session['user_id'],
            'update_config_general',
            f'Configuración general actualizada: {config["sistema_nombre"]}',
            request.remote_addr
        )
        
        logger.info(f"✅ Configuración general guardada: {config}")
        
        return jsonify({
            'success': True,
            'message': 'Configuración general guardada correctamente',
            'config': config
        })
        
    except Exception as e:
        logger.error(f"❌ Error guardando config general: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/admin/usuarios/<int:user_id>/editar', methods=['POST'])
@login_required
def editar_usuario_admin(user_id):
    """Editar usuario existente - CORREGIDA"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        # No permitir que se edite a sí mismo por seguridad
        if user_id == session['user_id']:
            return jsonify({'success': False, 'error': 'No puede editarse a sí mismo'})
        
        # ✅ OBTENER DATOS
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        role = data.get('role', 'user')
        is_active = data.get('is_active', True)
        
        # ✅ VALIDACIONES
        if not username or len(username) < 3:
            return jsonify({'success': False, 'error': 'El nombre de usuario debe tener al menos 3 caracteres'})
        
        if not email or '@' not in email:
            return jsonify({'success': False, 'error': 'Email inválido'})
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'})
        
        try:
            with conn.cursor() as cursor:
                # Verificar que el usuario existe
                cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                old_user = cursor.fetchone()
                if not old_user:
                    return jsonify({'success': False, 'error': 'Usuario no encontrado'})
                
                # Verificar duplicados (excluyendo el usuario actual)
                cursor.execute("""
                    SELECT id FROM users 
                    WHERE (username = %s OR email = %s) AND id != %s
                """, (username, email, user_id))
                
                if cursor.fetchone():
                    return jsonify({'success': False, 'error': 'El usuario o email ya existe'})
                
                # ✅ OBTENER ROLE_ID CORRECTAMENTE
                cursor.execute("SELECT id FROM roles WHERE name = %s", (role,))
                role_result = cursor.fetchone()
                
                if not role_result:
                    return jsonify({'success': False, 'error': f'Rol {role} no encontrado'})
                
                role_id = role_result[0]
                
                # ✅ ACTUALIZAR USUARIO CON ROLE_ID - NO ROLE
                cursor.execute("""
                    UPDATE users SET 
                        username = %s,
                        email = %s,
                        first_name = %s,
                        last_name = %s,
                        role_id = %s,
                        is_active = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (username, email, first_name, last_name, role_id, is_active, user_id))
                
                conn.commit()
                
                # ✅ REGISTRAR ACTIVIDAD
                registrar_actividad_usuario(
                    session['user_id'],
                    'update_user',
                    f'Usuario actualizado: {old_user[0]} → {username}',
                    request.remote_addr
                )
                
                logger.info(f"✅ Usuario actualizado: {username} (ID: {user_id})")
                
                return jsonify({
                    'success': True,
                    'message': f'Usuario {username} actualizado correctamente'
                })
                
        except Exception as e:
            conn.rollback()
            logger.error(f"❌ Error actualizando usuario: {e}")
            return jsonify({'success': False, 'error': str(e)})
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"❌ Error en editar usuario: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/usuarios/<int:user_id>/eliminar', methods=['DELETE'])
@login_required
def eliminar_usuario_admin(user_id):
    """Eliminar usuario (soft delete) - CORREGIDA"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        # No permitir eliminar el propio usuario o el admin principal
        if user_id == session['user_id']:
            return jsonify({'success': False, 'error': 'No puede eliminarse a sí mismo'})
        
        if user_id == 1:  # Proteger admin principal
            return jsonify({'success': False, 'error': 'No se puede eliminar el administrador principal'})
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'})
        
        try:
            with conn.cursor() as cursor:
                # ✅ CORREGIR CONSULTA - USAR ROLE_ID CON JOIN
                cursor.execute("""
                    SELECT u.username, COALESCE(r.name, 'user') as role_name
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    WHERE u.id = %s
                """, (user_id,))
                
                user_info = cursor.fetchone()
                if not user_info:
                    return jsonify({'success': False, 'error': 'Usuario no encontrado'})
                
                username, role_name = user_info
                
                # ✅ SOFT DELETE - DESACTIVAR EN LUGAR DE ELIMINAR
                cursor.execute("""
                    UPDATE users SET 
                        is_active = FALSE,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (user_id,))
                
                conn.commit()
                
                # ✅ REGISTRAR ACTIVIDAD
                registrar_actividad_usuario(
                    session['user_id'],
                    'delete_user',
                    f'Usuario eliminado: {username} ({role_name})',
                    request.remote_addr
                )
                
                logger.info(f"✅ Usuario eliminado: {username} (ID: {user_id})")
                
                return jsonify({
                    'success': True,
                    'message': f'Usuario {username} eliminado correctamente'
                })
                
        except Exception as e:
            conn.rollback()
            logger.error(f"❌ Error eliminando usuario: {e}")
            return jsonify({'success': False, 'error': str(e)})
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"❌ Error en eliminar usuario: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/logs/sistema')
@login_required
def obtener_logs_sistema():
    """Obtiene logs del sistema para el panel admin"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'})
        
        limit = request.args.get('limit', 50, type=int)
        filtro = request.args.get('filter', '')
        
        logs = []
        
        # ✅ LOGS DE ACTIVIDAD DE USUARIOS
        conn = obtener_conexion()
        if conn:
            with conn.cursor() as cursor:
                query = """
                    SELECT 
                        ua.timestamp,
                        u.username,
                        ua.action,
                        ua.details,
                        ua.ip_address
                    FROM user_activity ua
                    LEFT JOIN users u ON ua.user_id = u.id
                    WHERE 1=1
                """
                params = []
                
                if filtro:
                    query += " AND (ua.action ILIKE %s OR ua.details ILIKE %s OR u.username ILIKE %s)"
                    params.extend([f'%{filtro}%', f'%{filtro}%', f'%{filtro}%'])
                
                query += " ORDER BY ua.timestamp DESC LIMIT %s"
                params.append(limit)
                
                cursor.execute(query, params)
                
                for row in cursor.fetchall():
                    logs.append({
                        'timestamp': row[0].isoformat() if row[0] else '',
                        'user': row[1] or 'Sistema',
                        'action': row[2] or 'unknown',
                        'details': row[3] or '',
                        'ip_address': row[4] or 'N/A',
                        'type': 'user_activity'
                    })
            
            conn.close()
        
        # ✅ LOGS DE ARCHIVO SI ESTÁN DISPONIBLES
        try:
            if os.path.exists('app.log'):
                with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-limit:]
                    
                    for line in lines:
                        if line.strip() and (not filtro or filtro.lower() in line.lower()):
                            # Parsear línea de log
                            parts = line.strip().split(' - ', 2)
                            if len(parts) >= 2:
                                logs.append({
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'user': 'Sistema',
                                    'action': parts[0],
                                    'details': parts[1] if len(parts) > 1 else '',
                                    'ip_address': 'localhost',
                                    'type': 'system_log'
                                })
        except Exception as e:
            logger.debug(f"Error leyendo app.log: {e}")
        
        # ✅ ORDENAR Y LIMITAR
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        logs = logs[:limit]
        
        return jsonify({
            'success': True,
            'logs': logs,
            'total': len(logs),
            'filtered': bool(filtro)
        })
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo logs: {e}")
        return jsonify({'success': False, 'error': str(e)})
def listar_usuarios_basico():
    """Función auxiliar para listar usuarios desde la BD"""
    try:
        conn = obtener_conexion()
        if not conn:
            logger.warning("⚠️ Sin conexión BD - usando datos por defecto")
            # Fallback con datos por defecto
            return [
                {
                    'id': 1,
                    'username': 'admin',
                    'email': 'admin@empresa.com',
                    'first_name': 'Super',
                    'last_name': 'Admin',
                    'role': 'admin',
                    'is_active': True,
                    'last_login': datetime.datetime.now(),  # ✅ CORREGIDO
                    'created_at': datetime.datetime.now()
                }
            ]
        
        usuarios = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        u.id,
                        u.username,
                        u.email,
                        u.first_name,
                        u.last_name,
                        COALESCE(r.name, 'user') as role,
                        u.is_active,
                        u.last_login,
                        u.created_at
                    FROM users u
                    LEFT JOIN roles r ON u.role_id = r.id
                    ORDER BY u.created_at DESC
                """)
                
                rows = cursor.fetchall()
                
                for row in rows:
                    usuarios.append({
                        'id': row['id'],
                        'username': row['username'],
                        'email': row['email'],
                        'first_name': row['first_name'] or '',
                        'last_name': row['last_name'] or '',
                        'role': row['role'],
                        'is_active': bool(row['is_active']),
                        'last_login': row['last_login'],
                        'created_at': row['created_at']
                    })
                
        except Exception as e:
            logger.error(f"Error en consulta usuarios: {e}")
            # Si hay error en la consulta, usar datos por defecto
            usuarios = [
                {
                    'id': 1,
                    'username': 'admin',
                    'email': 'admin@empresa.com',
                    'first_name': 'Super',
                    'last_name': 'Admin',
                    'role': 'admin',
                    'is_active': True,
                    'last_login': datetime.datetime.now(),
                    'created_at': datetime.datetime.now()
                }
            ]
        
        finally:
            conn.close()
        
        logger.info(f"✅ Usuarios listados: {len(usuarios)}")
        return usuarios
        
    except Exception as e:
        logger.error(f"❌ Error listando usuarios: {e}")
        # Fallback final
        return [
            {
                'id': 1,
                'username': 'admin',
                'email': 'admin@empresa.com',
                'first_name': 'Super',
                'last_name': 'Admin',
                'role': 'admin',
                'is_active': True,
                'last_login': datetime.datetime.now(),
                'created_at': datetime.datetime.now()
            }
        ]
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
@login_required  # Cambiar de @admin_required a @login_required si es necesario
def cambiar_password_admin(user_id):
    """Cambia la contraseña de un usuario desde admin - CORREGIDA"""
    try:
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Acceso denegado'}), 403
        
        # Obtener contraseñas del FormData
        nueva_password = request.form.get('nueva_password')
        confirmar_password = request.form.get('confirmar_password')
        
        # Validaciones
        if not nueva_password or not confirmar_password:
            return jsonify({'success': False, 'error': 'Ambas contraseñas son requeridas'}), 400
        
        if nueva_password != confirmar_password:
            return jsonify({'success': False, 'error': 'Las contraseñas no coinciden'}), 400
        
        if len(nueva_password) < 6:
            return jsonify({'success': False, 'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'}), 500
        
        try:
            with conn.cursor() as cursor:
                # Verificar que el usuario existe
                cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                user_info = cursor.fetchone()
                if not user_info:
                    return jsonify({'success': False, 'error': 'Usuario no encontrado'}), 404
                
                username = user_info[0]
                
                # Actualizar contraseña con hash SHA-256
                password_hash = hashlib.sha256(nueva_password.encode()).hexdigest()
                cursor.execute("""
                    UPDATE users SET 
                        password_hash = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (password_hash, user_id))
                
                conn.commit()
                
                # Registrar actividad
                registrar_actividad_usuario(
                    session['user_id'],
                    'admin_change_password',
                    f'Contraseña cambiada para usuario: {username}',
                    request.remote_addr
                )
                
                logger.info(f"✅ Contraseña cambiada por admin para usuario: {username}")
                
                return jsonify({
                    'success': True,
                    'message': f'Contraseña actualizada para {username}'
                })
                
        except Exception as e:
            conn.rollback()
            logger.error(f"❌ Error cambiando contraseña: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"❌ Error en cambio de contraseña admin: {e}")
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

# time_ago duplicado eliminado
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
            'system': {
                'timestamp': datetime.datetime.now().isoformat(),
                'uptime': time.time() - start_time if 'start_time' in globals() else 0
            }
        }
        
        return jsonify({'success': True, 'status': status})
        
    except Exception as e:
        logger.error(f"Error obteniendo estado del dashboard: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Variable para tracking de uptime de la aplicación
app_start_time = time.time()

# BUSCAR @app.route('/api/dashboard/counters') Y REEMPLAZAR COMPLETAMENTE:

# BUSCAR @app.route('/api/dashboard/counters') Y REEMPLAZAR COMPLETAMENTE:

@app.route('/api/dashboard/counters')
@login_required
def get_dashboard_counters():
    """Obtiene contadores desde la tabla de estadísticas optimizada"""
    try:
        conn = obtener_conexion()
        
        if not conn:
            logger.error("❌ Sin conexión a BD para contadores")
            return jsonify({
                'success': False,
                'error': 'Sin conexión a BD',
                'counters': {
                    'total_analizados': 0,
                    'total_detecciones': 0,
                    'sospechosas': 0,
                    'alertas_criticas': 0,
                    'clientes_activos': 0,
                }
            }), 500
        
        try:
            with conn.cursor() as cursor:
                # ✅ CONSULTA OPTIMIZADA - SOLO UN SELECT A detection_stats
                cursor.execute("""
                    SELECT 
                        total_packets_scanned,
                        total_detections,
                        total_suspicious,
                        total_high,
                        last_updated
                    FROM detection_stats
                    ORDER BY last_updated DESC
                    LIMIT 1;
                """)
                
                result = cursor.fetchone()
                logger.info(f"📊 Resultado query contadores: {result}")
                
                # ✅ CONTADORES DESDE detection_stats
                if result:
                    counters = {
                        'total_analizados': result[0] or 0,        # total_packets_scanned
                        'total_detecciones': result[1] or 0,       # total_detections
                        'sospechosas': result[2] or 0,             # total_suspicious
                        'alertas_criticas': result[3] or 0,        # total_critical
                        'ultima_actualizacion': result[4].isoformat() if result[4] else None
                    }
                else:
                    logger.warning("⚠️ No hay datos en detection_stats")
                    counters = {
                        'total_analizados': 0,
                        'total_detecciones': 0,
                        'sospechosas': 0,
                        'alertas_criticas': 0,
                        'ultima_actualizacion': None
                    }
                
                # ✅ CLIENTES ACTIVOS - SEPARADO Y MEJORADO
                try:
                    # Contar clientes federados en BD
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_clients,
                            COUNT(*) FILTER (WHERE status = 'active' AND last_seen >= NOW() - INTERVAL '5 minutes') as active_clients
                        FROM federated_clients
                    """)
                    
                    client_result = cursor.fetchone()
                    db_active_clients = client_result[1] if client_result else 0
                    db_total_clients = client_result[0] if client_result else 0
                    
                    # ✅ VERIFICAR DETECTOR LOCAL (COMO ANTES)
                    detector_running = detector_process is not None and detector_process.poll() is None
                    
                    # Si el detector local está corriendo, contar como cliente activo
                    if detector_running:
                        counters['clientes_activos'] = max(db_active_clients, 1)
                        counters['total_clientes'] = max(db_total_clients, 1)
                    else:
                        counters['clientes_activos'] = db_active_clients
                        counters['total_clientes'] = db_total_clients
                    
                    # ✅ INFORMACIÓN ADICIONAL DEL DETECTOR
                    counters['detector_local'] = {
                        'running': detector_running,
                        'status': detector_stats.get('status', 'stopped'),
                        'interface': detector_stats.get('interface', 'N/A'),
                        'uptime': int(time.time() - detector_stats['start_time']) if detector_stats.get('start_time') else 0
                    }
                    
                    logger.info(f"✅ Clientes activos: {counters['clientes_activos']} (BD: {db_active_clients}, Local: {detector_running})")
                    
                except Exception as e:
                    logger.error(f"Error consultando clientes: {e}")
                    # Fallback con detector local solamente
                    detector_running = detector_process is not None and detector_process.poll() is None
                    counters['clientes_activos'] = 1 if detector_running else 0
                    counters['total_clientes'] = 1 if detector_running else 0
                    counters['detector_local'] = {
                        'running': detector_running,
                        'status': detector_stats.get('status', 'stopped'),
                        'interface': detector_stats.get('interface', 'N/A'),
                        'uptime': 0
                    }
        
        except Exception as e:
            logger.error(f"❌ Error consultando estadísticas: {e}")
            return jsonify({
                'success': False,
                'error': str(e),
                'counters': {
                    'total_analizados': 0,
                    'total_detecciones': 0,
                    'sospechosas': 0,
                    'alertas_criticas': 0,
                    'clientes_activos': 0,
                }
            }), 500
        finally:
            conn.close()
        
        return jsonify({
            'success': True,
            'counters': counters,
            'timestamp': datetime.datetime.now().isoformat(),
            'source': 'optimized_stats_table_with_clients'
        })

    except Exception as e:
        logger.error(f"❌ Error obteniendo contadores: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'counters': {
                'total_analizados': 0,
                'total_detecciones': 0,
                'sospechosas': 0,
                'alertas_criticas': 0,
                'clientes_activos': 0,
            }
        }), 500
    
@app.route('/api/dashboard/detailed-stats')
@login_required
def get_detailed_stats():
    """Obtiene estadísticas detalladas desde la tabla optimizada"""
    try:
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Sin conexión BD'})
        
        with conn.cursor() as cursor:
            # Estadísticas principales
            cursor.execute("""
                SELECT 
                    total_packets_scanned,
                    total_detections,
                    total_suspicious,
                    total_critical,
                    total_high,
                    total_medium,
                    total_low,
                    normal_traffic,
                    last_updated
                FROM detection_stats 
                WHERE id = 1
            """)
            
            stats = cursor.fetchone()
            
            if not stats:
                return jsonify({
                    'success': True,
                    'stats': {
                        'total_packets_scanned': 0,
                        'distribution_by_severity': {},
                        'distribution_by_type': {},
                        'last_updated': None
                    }
                })
            
            # Calcular distribuciones
            total_all = stats[1] + stats[7]  # detecciones + normal
            
            severity_distribution = {
                'critical': {'count': stats[3], 'percentage': 0},
                'high': {'count': stats[4], 'percentage': 0},
                'medium': {'count': stats[5], 'percentage': 0},
                'low': {'count': stats[6], 'percentage': 0}
            }
            
            type_distribution = {
                'normal': {'count': stats[7], 'percentage': 0},
                'suspicious': {'count': stats[2], 'percentage': 0},
                'other_detections': {'count': stats[1] - stats[2], 'percentage': 0}
            }
            
            # Calcular porcentajes
            if total_all > 0:
                for severity in severity_distribution:
                    count = severity_distribution[severity]['count']
                    severity_distribution[severity]['percentage'] = round((count / total_all) * 100, 2)
                
                for type_name in type_distribution:
                    count = type_distribution[type_name]['count']
                    type_distribution[type_name]['percentage'] = round((count / total_all) * 100, 2)
            
            detailed_stats = {
                'total_packets_scanned': stats[0],
                'total_detections': stats[1],
                'total_suspicious': stats[2],
                'normal_traffic': stats[7],
                'distribution_by_severity': severity_distribution,
                'distribution_by_type': type_distribution,
                'last_updated': stats[8].isoformat() if stats[8] else None,
                'summary': {
                    'detection_rate': round((stats[1] / max(1, stats[0])) * 100, 2),
                    'suspicious_rate': round((stats[2] / max(1, stats[1])) * 100, 2) if stats[1] > 0 else 0,
                    'critical_rate': round((stats[3] / max(1, stats[1])) * 100, 2) if stats[1] > 0 else 0
                }
            }
            
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': detailed_stats,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas detalladas: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
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
                
                logger.info(f"  Detecciones recientes obtenidas: {len(detections)}")
                
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
        
        #   GUARDAR DIRECTAMENTE EN POSTGRESQL:
        success = save_detection_to_database(detection_data)
        
        #   ACTUALIZAR STATS PARA DASHBOARD:
        
        stats_buffer.add_detection(detection_data)
        
        if success:
            logger.info(f"  Detección guardada | Usuario: {user_id} | Tipo: {detection_data.get('anomaly_type')}")
            return jsonify({'success': True, 'message': 'Detección guardada exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error guardando en BD'}), 500
        
    except Exception as e:
        logger.error(f"  Error procesando detección: {e}")
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
#REPORTES
@app.route('/reportes/fechas')
@login_required
def reportes_fechas():
    """Página de reportes por fechas"""
    try:
        user = obtener_usuario_por_id(session['user_id'])
        if not user:
            flash('Error al obtener información del usuario', 'danger')
            return redirect(url_for('login'))
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'access_reportes_fechas',
            'Acceso a reportes por fechas',
            request.remote_addr
        )
        
        return render_template('reportes_fechas.html', user=user)
        
    except Exception as e:
        logger.error(f"Error en reportes por fechas: {e}")
        flash('Error al cargar la página de reportes por fechas', 'danger')
        return render_template('reportes_fechas.html', 
                             user={'username': session.get('username', 'Usuario')})

@app.route('/api/reportes/datos-fechas', methods=['POST'])
@login_required
def api_reportes_datos_fechas():
    """API COMPLETA para obtener datos filtrados por fechas y horas - CORREGIDA"""
    from datetime import datetime, timedelta
    import traceback
    from psycopg2.extras import RealDictCursor
    
    try:
        filtros = request.get_json()
        logger.info(f"🔍 Filtros recibidos: {filtros}")
        
        # Verificar conexión a BD
        conn = obtener_conexion()
        if not conn:
            logger.error("❌ Error de conexión a BD")
            return jsonify({'success': False, 'error': 'Error de conexión a base de datos'}), 500
        
        # ✅ CONSULTA CORREGIDA - SIN DETECTION_ID PROBLEMÁTICO
        query = """
        SELECT 
            d.id,
            d.timestamp,
            COALESCE(d.source_ip::text, '0.0.0.0') as source_ip,
            COALESCE(d.destination_ip::text, '0.0.0.0') as destination_ip,
            COALESCE(d.source_port, 0) as source_port,
            COALESCE(d.destination_port, 0) as destination_port,
            COALESCE(d.anomaly_type, 'Desconocido') as anomaly_type,
            COALESCE(d.severity, 'medium') as severity,
            COALESCE(d.confidence_score, 0.5) as confidence_score,
            COALESCE(d.client_id, 1) as client_id,
            COALESCE(d.protocol, 'TCP') as protocol,
            CASE 
                WHEN d.detection_id IS NULL THEN 'N/A'
                ELSE d.detection_id::text 
            END as detection_id
        FROM detections d
        WHERE d.timestamp BETWEEN %s AND %s
        ORDER BY d.timestamp DESC
        --LIMIT 1000
        """
        
        # ✅ PARSING MEJORADO DE FECHAS CON SOPORTE PARA "a"
        fecha_inicio = None
        fecha_fin = None
        rango_fechas = filtros.get('rango_fechas', '').strip()
        
        logger.info(f"📅 Procesando rango: '{rango_fechas}'")
        
        if rango_fechas:
            try:
                # ✅ NORMALIZAR SEPARADORES ANTES DE PARSEAR
                rango_normalizado = rango_fechas
                
                # Reemplazar " a " por " - " para normalizar
                if ' a ' in rango_normalizado:
                    rango_normalizado = rango_normalizado.replace(' a ', ' - ')
                    logger.info(f"📅 Rango normalizado: '{rango_normalizado}'")
                
                if ' - ' in rango_normalizado:
                    # ✅ RANGO COMPLETO: "DD/MM/YYYY HH:MM - DD/MM/YYYY HH:MM"
                    fechas = rango_normalizado.split(' - ')
                    fecha_inicio_str = fechas[0].strip()
                    fecha_fin_str = fechas[1].strip()
                    
                    # Parsear fecha de inicio
                    fecha_inicio = parsear_fecha_con_hora_mejorada(fecha_inicio_str, es_inicio=True)
                    fecha_fin = parsear_fecha_con_hora_mejorada(fecha_fin_str, es_inicio=False)
                    
                else:
                    # ✅ FECHA ÚNICA: "DD/MM/YYYY" o "DD/MM/YYYY HH:MM"
                    if ':' in rango_normalizado:
                        # Con hora específica: ±30 minutos
                        fecha_central = parsear_fecha_con_hora_mejorada(rango_normalizado, es_inicio=None)
                        fecha_inicio = fecha_central - timedelta(minutes=30)
                        fecha_fin = fecha_central + timedelta(minutes=30)
                    else:
                        # Solo fecha: todo el día
                        fecha_inicio = parsear_fecha_con_hora_mejorada(rango_normalizado, es_inicio=True)
                        fecha_fin = parsear_fecha_con_hora_mejorada(rango_normalizado, es_inicio=False)
                
                logger.info(f"📅 Rango parseado: {fecha_inicio} a {fecha_fin}")
                
            except Exception as e:
                logger.error(f"❌ Error parseando fechas: {e}")
                return jsonify({
                    'success': False, 
                    'error': f'Error en formato de fechas: {str(e)}. Use DD/MM/YYYY o DD/MM/YYYY HH:MM'
                }), 400
        else:
            # Rango por defecto: últimos 30 días
            fecha_fin = datetime.now()
            fecha_inicio = fecha_fin - timedelta(days=30)
            logger.info("📅 Usando rango por defecto: últimos 30 días")
        
        # ✅ EJECUTAR CONSULTA CORREGIDA
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            logger.info(f"🔍 CONSULTA SQL CORREGIDA ejecutándose...")
            logger.info(f"🔍 PARÁMETRO 1 (inicio): {fecha_inicio}")
            logger.info(f"🔍 PARÁMETRO 2 (fin): {fecha_fin}")
            
            cursor.execute(query, [fecha_inicio, fecha_fin])
            resultados = cursor.fetchall()
            
            logger.info(f"📊 REGISTROS ENCONTRADOS: {len(resultados)}")
            
            # ✅ ESTADÍSTICAS DETALLADAS
            stats_query = """
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as criticas,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as altas,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medias,
                COUNT(CASE WHEN severity = 'low' THEN 1 END) as bajas,
                MIN(timestamp) as fecha_minima,
                MAX(timestamp) as fecha_maxima,
                COUNT(DISTINCT source_ip) as ips_origen_unicas,
                COUNT(DISTINCT destination_ip) as ips_destino_unicas,
                COUNT(DISTINCT client_id) as clientes_detectando
            FROM detections d
            WHERE d.timestamp BETWEEN %s AND %s
            """
            
            cursor.execute(stats_query, [fecha_inicio, fecha_fin])
            stats = cursor.fetchone()
            
            logger.info(f"📊 ESTADÍSTICAS: {dict(stats) if stats else 'None'}")
        
        conn.close()
        
        # ✅ CONVERTIR RESULTADOS A JSON
        datos_json = []
        for row in resultados:
            datos_json.append({
                'id': row['id'],
                'detection_id': row['detection_id'],  # Ya está como texto
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else '',
                'client_id': row['client_id'],
                'severity': row['severity'],
                'anomaly_type': row['anomaly_type'],
                'source_ip': str(row['source_ip']),
                'source_port': int(row['source_port']),
                'destination_ip': str(row['destination_ip']),
                'destination_port': int(row['destination_port']),
                'protocol': row['protocol'],
                'confidence_score': float(row['confidence_score'])
            })
        
        # ✅ ESTADÍSTICAS COMPLETAS
        estadisticas = {
            'total': int(stats['total']) if stats and stats['total'] else 0,
            'criticas': int(stats['criticas']) if stats and stats['criticas'] else 0,
            'altas': int(stats['altas']) if stats and stats['altas'] else 0,
            'medias': int(stats['medias']) if stats and stats['medias'] else 0,
            'bajas': int(stats['bajas']) if stats and stats['bajas'] else 0,
            'fecha_minima': stats['fecha_minima'].isoformat() if stats and stats['fecha_minima'] else None,
            'fecha_maxima': stats['fecha_maxima'].isoformat() if stats and stats['fecha_maxima'] else None,
            'ips_origen_unicas': int(stats['ips_origen_unicas']) if stats and stats['ips_origen_unicas'] else 0,
            'ips_destino_unicas': int(stats['ips_destino_unicas']) if stats and stats['ips_destino_unicas'] else 0,
            'clientes_detectando': int(stats['clientes_detectando']) if stats and stats['clientes_detectando'] else 0
        }
        
        logger.info(f"✅ RESPUESTA FINAL: {len(datos_json)} registros")
        
        return jsonify({
            'success': True,
            'datos': datos_json,
            'estadisticas': estadisticas,
            'filtros_aplicados': {
                'rango_original': rango_fechas,
                'rango_normalizado': rango_normalizado if 'rango_normalizado' in locals() else rango_fechas,
                'fecha_inicio': fecha_inicio.isoformat() if fecha_inicio else None,
                'fecha_fin': fecha_fin.isoformat() if fecha_fin else None,
                'total_encontrados': len(datos_json)
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error en API: {str(e)}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Error interno: {str(e)}'
        }), 500

def parsear_fecha_con_hora_mejorada(fecha_str, es_inicio=True):
    """Función auxiliar mejorada para parsear fechas con diferentes formatos"""
    from datetime import datetime
    
    # ✅ FORMATOS SOPORTADOS AMPLIADOS
    formatos = [
        '%d/%m/%Y %H:%M:%S',    # DD/MM/YYYY HH:MM:SS
        '%d/%m/%Y %H:%M',       # DD/MM/YYYY HH:MM
        '%d/%m/%Y',             # DD/MM/YYYY
        '%Y-%m-%d %H:%M:%S',    # YYYY-MM-DD HH:MM:SS
        '%Y-%m-%d %H:%M',       # YYYY-MM-DD HH:MM
        '%Y-%m-%d',             # YYYY-MM-DD
        '%d-%m-%Y %H:%M:%S',    # DD-MM-YYYY HH:MM:SS
        '%d-%m-%Y %H:%M',       # DD-MM-YYYY HH:MM
        '%d-%m-%Y'              # DD-MM-YYYY
    ]
    
    # ✅ LIMPIAR STRING DE ENTRADA
    fecha_str = fecha_str.strip()
    
    for formato in formatos:
        try:
            fecha = datetime.strptime(fecha_str, formato)
            
            # Si no tiene hora especificada, agregar hora según el contexto
            if '%H' not in formato:
                if es_inicio is True:
                    # Inicio del día: 00:00:00
                    fecha = fecha.replace(hour=0, minute=0, second=0, microsecond=0)
                elif es_inicio is False:
                    # Final del día: 23:59:59
                    fecha = fecha.replace(hour=23, minute=59, second=59, microsecond=999999)
                # Si es_inicio es None, mantener la hora parseada
            
            return fecha
            
        except ValueError:
            continue
    
    # ✅ ERROR MÁS DESCRIPTIVO
    raise ValueError(f"Formato de fecha no reconocido: '{fecha_str}'. Use formatos como DD/MM/YYYY, DD/MM/YYYY HH:MM")

@app.route('/api/reportes/generar-fechas', methods=['POST'])
@login_required
def api_reportes_generar_fechas():
    """API SIMPLIFICADA para generar reportes - SOLO EXPORTAR CONSULTA"""
    from datetime import datetime, timedelta
    import pandas as pd
    import os
    
    try:
        data = request.get_json()
        filtros = data.get('filtros', {})
        formato = data.get('formato', 'excel')
        
        logger.info(f"📊 Generando reporte simple: {filtros}, formato: {formato}")
        
        # ✅ OBTENER CONEXIÓN
        conn = obtener_conexion()
        if not conn:
            return jsonify({'success': False, 'error': 'Error de conexión a BD'}), 500
        
        # ✅ PARSEAR FECHAS (LÓGICA SIMPLE)
        rango_fechas = filtros.get('rango_fechas', '').strip()
        
        if rango_fechas:
            # Normalizar "a" por "-"
            if ' a ' in rango_fechas:
                rango_fechas = rango_fechas.replace(' a ', ' - ')
            
            if ' - ' in rango_fechas:
                fechas = rango_fechas.split(' - ')
                fecha_inicio = parsear_fecha_con_hora_mejorada(fechas[0].strip(), es_inicio=True)
                fecha_fin = parsear_fecha_con_hora_mejorada(fechas[1].strip(), es_inicio=False)
            else:
                if ':' in rango_fechas:
                    fecha_central = parsear_fecha_con_hora_mejorada(rango_fechas, es_inicio=None)
                    fecha_inicio = fecha_central - timedelta(minutes=30)
                    fecha_fin = fecha_central + timedelta(minutes=30)
                else:
                    fecha_inicio = parsear_fecha_con_hora_mejorada(rango_fechas, es_inicio=True)
                    fecha_fin = parsear_fecha_con_hora_mejorada(rango_fechas, es_inicio=False)
        else:
            # Últimos 30 días por defecto
            fecha_fin = datetime.now()
            fecha_inicio = fecha_fin - timedelta(days=30)
        
        # ✅ CONSULTA SIMPLE - IGUAL QUE LA DE VISTA PREVIA
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN d.detection_id IS NULL THEN 'N/A'
                        ELSE d.detection_id::text 
                    END as "ID Detección",
                    d.timestamp as "Fecha/Hora",
                    COALESCE(d.anomaly_type, 'Desconocido') as "Tipo de Amenaza",
                    COALESCE(d.severity, 'medium') as "Severidad",
                    COALESCE(d.confidence_score, 0.5) as "Confianza",
                    COALESCE(d.source_ip::text, '0.0.0.0') as "IP Origen",
                    COALESCE(d.source_port, 0) as "Puerto Origen",
                    COALESCE(d.destination_ip::text, '0.0.0.0') as "IP Destino",
                    COALESCE(d.destination_port, 0) as "Puerto Destino",
                    COALESCE(d.protocol, 'TCP') as "Protocolo",
                    COALESCE(d.client_id, 1) as "Cliente ID"
                FROM detections d
                WHERE d.timestamp BETWEEN %s AND %s
                ORDER BY d.timestamp DESC
            """, [fecha_inicio, fecha_fin])
            
            resultados = cursor.fetchall()
        
        conn.close()
        
        # ✅ VERIFICAR SI HAY DATOS
        if not resultados:
            return jsonify({
                'success': False,
                'error': 'No se encontraron detecciones en el rango de fechas especificado'
            }), 400
        
        # ✅ CONVERTIR A DATAFRAME
        df = pd.DataFrame([dict(row) for row in resultados])
        
        # ✅ FORMATEAR FECHA/HORA PARA MEJOR VISUALIZACIÓN
        if 'Fecha/Hora' in df.columns:
            df['Fecha/Hora'] = pd.to_datetime(df['Fecha/Hora']).dt.strftime('%d/%m/%Y %H:%M:%S')
        
        if 'Confianza' in df.columns:
            df['Confianza'] = pd.to_numeric(df['Confianza'], errors='coerce')
            df['Confianza'] = df['Confianza'].round(3)
        
        # ✅ CREAR DIRECTORIO DE REPORTES
        reports_dir = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), 'reportes')
        os.makedirs(reports_dir, exist_ok=True)
        
        # ✅ GENERAR NOMBRE DE ARCHIVO
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        fecha_rango_str = f"{fecha_inicio.strftime('%d%m%Y')}_{fecha_fin.strftime('%d%m%Y')}"
        
        if formato.lower() == 'excel':
            filename = f"detecciones_{fecha_rango_str}_{timestamp}.xlsx"
            filepath = os.path.join(reports_dir, filename)
            
            # ✅ EXPORTAR A EXCEL SIMPLE
            df.to_excel(filepath, index=False, engine='openpyxl')
            
        elif formato.lower() == 'csv':
            filename = f"detecciones_{fecha_rango_str}_{timestamp}.csv"
            filepath = os.path.join(reports_dir, filename)
            
            # ✅ EXPORTAR A CSV CON UTF-8
            df.to_csv(filepath, index=False, encoding='utf-8-sig', sep=';')
            
        else:
            return jsonify({'success': False, 'error': f'Formato no soportado: {formato}'}), 400
        
        # ✅ REGISTRAR ACTIVIDAD
        try:
            registrar_actividad_usuario(
                session['user_id'],
                'generar_reporte',
                f'Reporte {formato.upper()} generado: {len(resultados)} detecciones',
                request.remote_addr
            )
        except:
            pass  # No fallar si hay error en el registro
        
        # ✅ RESPUESTA EXITOSA
        download_url = f'/api/reportes/descargar/{filename}'
        file_size = os.path.getsize(filepath) / 1024 if os.path.exists(filepath) else 0
        
        logger.info(f"✅ Reporte generado: {filepath} ({len(resultados)} registros)")
        
        return jsonify({
            'success': True,
            'message': f'Reporte {formato.upper()} generado exitosamente',
            'download_url': download_url,
            'filename': filename,
            'registros_incluidos': len(resultados),
            'rango_fechas': f"{fecha_inicio.strftime('%d/%m/%Y %H:%M')} - {fecha_fin.strftime('%d/%m/%Y %H:%M')}",
            'formato': formato.upper(),
            'tamaño_archivo': f"{file_size:.1f} KB"
        })
        
    except Exception as e:
        logger.error(f"❌ Error generando reporte: {e}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f'Error generando reporte: {str(e)}'
        }), 500

@app.route('/api/reportes/descargar/<filename>')
@login_required
def descargar_reporte(filename):
    """Descarga un archivo de reporte generado"""
    try:
        reports_dir = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), 'reportes')
        filepath = os.path.join(reports_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Determinar tipo MIME
        if filename.lower().endswith('.xlsx'):
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif filename.lower().endswith('.csv'):
            mimetype = 'text/csv'
        else:
            mimetype = 'application/octet-stream'
        
        logger.info(f"📥 Descargando: {filename}")
        
        return send_from_directory(
            reports_dir,
            filename,
            as_attachment=True,
            mimetype=mimetype
        )
        
    except Exception as e:
        logger.error(f"❌ Error descargando: {e}")
        return jsonify({'error': 'Error descargando archivo'}), 500
    
@app.route('/api/reportes/listar-archivos')
@login_required 
def listar_reportes_generados():
    """Lista archivos de reportes disponibles para descarga"""
    try:
        reports_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'reportes')
        
        if not os.path.exists(reports_dir):
            return jsonify({'success': True, 'archivos': []})
        
        archivos = []
        for filename in os.listdir(reports_dir):
            if filename.lower().endswith(('.xlsx', '.csv')):
                filepath = os.path.join(reports_dir, filename)
                stat = os.stat(filepath)
                
                # ✅ CORREGIR EL IMPORT - USAR datetime.datetime
                archivos.append({
                    'nombre': filename,
                    'tamaño': f"{stat.st_size / 1024:.1f} KB",
                    'fecha_creacion': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%d/%m/%Y %H:%M'),
                    'fecha_modificacion': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%d/%m/%Y %H:%M'),
                    'tipo': 'Excel' if filename.lower().endswith('.xlsx') else 'CSV',
                    'download_url': f'/api/reportes/descargar/{filename}'
                })
        
        # Ordenar por fecha de creación (más recientes primero)
        archivos.sort(key=lambda x: x['fecha_creacion'], reverse=True)
        
        return jsonify({
            'success': True,
            'archivos': archivos,
            'total': len(archivos)
        })
        
    except Exception as e:
        logger.error(f"❌ Error listando reportes: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/reportes/limpiar-archivos', methods=['POST'])
@admin_required
def limpiar_reportes_antiguos():
    """Limpia reportes antiguos (solo admin)"""
    try:
        reports_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'reportes')
        
        if not os.path.exists(reports_dir):
            return jsonify({'success': True, 'message': 'No hay reportes para limpiar'})
        
        archivos_eliminados = 0
        ahora = time.time()
        dias_limite = 30  # Eliminar archivos de más de 30 días
        
        for filename in os.listdir(reports_dir):
            if filename.lower().endswith(('.xlsx', '.csv')):
                filepath = os.path.join(reports_dir, filename)
                
                # Verificar antigüedad
                if (ahora - os.path.getctime(filepath)) > (dias_limite * 24 * 60 * 60):
                    try:
                        os.remove(filepath)
                        archivos_eliminados += 1
                        logger.info(f"🗑️ Archivo eliminado: {filename}")
                    except Exception as e:
                        logger.error(f"Error eliminando {filename}: {e}")
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'limpiar_reportes',
            f'Limpieza de reportes: {archivos_eliminados} archivos eliminados',
            request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'message': f'Limpieza completada: {archivos_eliminados} archivos eliminados',
            'archivos_eliminados': archivos_eliminados
        })
        
    except Exception as e:
        logger.error(f"❌ Error limpiando reportes: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
# AGREGAR ESTAS RUTAS API DESPUÉS DE LA LÍNEA 3008 EN main.py

# ========================================
# 📅 APIS PARA CALENDARIO DE DETECCIONES - CORREGIDAS
# ========================================

@app.route('/api/calendario/datos', methods=['POST'])
@login_required
def api_calendario_datos():
    """API para obtener datos del calendario de detecciones"""
    try:
        from datetime import datetime  # Import local para evitar conflictos
        
        data = request.get_json()
        year = int(data.get('year', datetime.now().year))
        month = int(data.get('month', datetime.now().month))
        
        logger.info(f"📅 Solicitud de datos calendario: {month}/{year}")
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({
                'success': False,
                'error': 'No se pudo conectar a la base de datos'
            })
        
        calendario_data = {}
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Obtener detecciones agrupadas por día
                cursor.execute("""
                    SELECT 
                        DATE(timestamp) as fecha,
                        COUNT(*) as total,
                        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
                        COUNT(CASE WHEN severity = 'high' THEN 1 END) as suspicious,
                        COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
                        COUNT(CASE WHEN severity = 'low' THEN 1 END) as low
                    FROM detections 
                    WHERE EXTRACT(YEAR FROM timestamp) = %s 
                      AND EXTRACT(MONTH FROM timestamp) = %s
                    GROUP BY DATE(timestamp)
                    ORDER BY fecha
                """, (year, month))
                
                rows = cursor.fetchall()
                
                for row in rows:
                    if row['fecha']:  # Verificar que la fecha no sea None
                        fecha_key = row['fecha'].strftime('%Y-%m-%d')
                        calendario_data[fecha_key] = {
                            'total': int(row['total'] or 0),
                            'critical': int(row['critical'] or 0),
                            'suspicious': int(row['suspicious'] or 0),  # high = sospechosas
                            'high': int(row['suspicious'] or 0),
                            'medium': int(row['medium'] or 0),
                            'low': int(row['low'] or 0)
                        }
            
        except Exception as e:
            logger.error(f"❌ Error en consulta calendario: {e}")
            calendario_data = {}
        
        finally:
            conn.close()
        
        logger.info(f"✅ Datos calendario enviados: {len(calendario_data)} días con actividad")
        
        return jsonify({
            'success': True,
            'datos': calendario_data,
            'mes': month,
            'año': year
        })
        
    except Exception as e:
        logger.error(f"❌ Error en API calendario: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/calendario/detalles-dia', methods=['POST'])
@login_required
def api_calendario_detalles_dia():
    """API para obtener detalles de detecciones de un día específico"""
    try:
        data = request.get_json()
        fecha = data.get('fecha')  # Formato: YYYY-MM-DD
        
        if not fecha:
            return jsonify({
                'success': False,
                'error': 'Fecha requerida'
            })
            
        logger.info(f"🔍 Solicitud detalles día: {fecha}")
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({
                'success': False,
                'error': 'No se pudo conectar a la base de datos'
            })
        
        detecciones = []
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT 
                        d.id,
                        d.timestamp,
                        COALESCE(d.anomaly_type, 'Desconocido') as anomaly_type,
                        COALESCE(d.severity, 'medium') as severity,
                        COALESCE(d.confidence_score, 0.5) as confidence_score,
                        COALESCE(d.source_ip::text, '0.0.0.0') as source_ip,
                        COALESCE(d.destination_ip::text, '0.0.0.0') as destination_ip,
                        COALESCE(d.source_port, 0) as source_port,
                        COALESCE(d.destination_port, 0) as destination_port,
                        COALESCE(d.protocol, 'TCP') as protocol,
                        COALESCE(fc.name, 'Cliente ' || d.client_id::text) as client_name
                    FROM detections d
                    LEFT JOIN federated_clients fc ON d.client_id = fc.id
                    WHERE DATE(d.timestamp) = %s
                    ORDER BY d.timestamp DESC
                    LIMIT 50
                """, (fecha,))
                
                rows = cursor.fetchall()
                
                for row in rows:
                    detecciones.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None,
                        'anomaly_type': row['anomaly_type'],
                        'severity': row['severity'],
                        'confidence_score': float(row['confidence_score']),
                        'source_ip': str(row['source_ip']),
                        'destination_ip': str(row['destination_ip']),
                        'source_port': int(row['source_port']),
                        'destination_port': int(row['destination_port']),
                        'protocol': row['protocol'],
                        'client_name': row['client_name']
                    })
        
        except Exception as e:
            logger.error(f"❌ Error en consulta detalles: {e}")
            detecciones = []
        
        finally:
            conn.close()
        
        logger.info(f"✅ Detalles día enviados: {len(detecciones)} detecciones")
        
        return jsonify({
            'success': True,
            'detecciones': detecciones,
            'fecha': fecha,
            'total': len(detecciones)
        })
        
    except Exception as e:
        logger.error(f"❌ Error en API detalles día: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })


    
@app.route('/reportes/calendario')
@login_required
def reportes_calendario():
    """Página de calendario de detecciones"""
    try:
        user = obtener_usuario_por_id(session['user_id'])
        if not user:
            flash('Error al obtener información del usuario', 'danger')
            return redirect(url_for('login'))
        
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'access_calendario',
            'Acceso al calendario de detecciones',
            request.remote_addr
        )
        
        return render_template('reportes_calendario.html', user=user)
        
    except Exception as e:
        logger.error(f"Error en calendario: {e}")
        flash('Error al cargar el calendario', 'danger')
        return render_template('reportes_calendario.html', 
                             user={'username': session.get('username', 'Usuario')})

@app.route('/api/reportes/generar-dia-excel', methods=['POST'])
@login_required
def api_generar_dia_excel():
    """API para generar reporte Excel de un día específico"""
    try:
        data = request.get_json()
        fecha = data.get('fecha')  # Formato: YYYY-MM-DD
        
        if not fecha:
            return jsonify({
                'success': False,
                'error': 'Fecha requerida'
            })
        
        logger.info(f"📊 Generando Excel para día: {fecha}")
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({
                'success': False,
                'error': 'No se pudo conectar a la base de datos'
            })
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Obtener detecciones del día
                cursor.execute("""
                    SELECT 
                        d.timestamp,
                        d.anomaly_type,
                        d.severity,
                        d.confidence_score,
                        d.source_ip,
                        d.destination_ip,
                        d.source_port,
                        d.destination_port,
                        d.protocol,
                        COALESCE(fc.name, 'Cliente ' || d.client_id::text) as client_name
                    FROM detections d
                    LEFT JOIN federated_clients fc ON d.client_id = fc.id
                    WHERE DATE(d.timestamp) = %s
                    ORDER BY d.timestamp DESC
                """, (fecha,))
                
                detecciones = cursor.fetchall()
                
        finally:
            conn.close()
        
        if not detecciones:
            return jsonify({
                'success': False,
                'error': 'No se encontraron detecciones para esta fecha'
            })
        
        # ✅ GENERAR ARCHIVO EXCEL
        import pandas as pd
        from datetime import datetime
        import os
        
        # Convertir datos a DataFrame
        df_data = []
        for det in detecciones:
            df_data.append({
                'Fecha/Hora': det['timestamp'].strftime('%d/%m/%Y %H:%M:%S') if det['timestamp'] else '',
                'Cliente': det['client_name'],
                'Tipo de Anomalía': det['anomaly_type'],
                'Severidad': det['severity'],
                'Confianza (%)': round(float(det['confidence_score']) * 100, 1) if det['confidence_score'] else 0,
                'IP Origen': str(det['source_ip']) if det['source_ip'] else '',
                'Puerto Origen': det['source_port'] if det['source_port'] else '',
                'IP Destino': str(det['destination_ip']) if det['destination_ip'] else '',
                'Puerto Destino': det['destination_port'] if det['destination_port'] else '',
                'Protocolo': det['protocol'] if det['protocol'] else ''
            })
        
        df = pd.DataFrame(df_data)
        
        # Crear directorio si no existe
        reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generar nombre de archivo
        fecha_formateada = datetime.strptime(fecha, '%Y-%m-%d').strftime('%d-%m-%Y')
        filename = f"detecciones_dia_{fecha_formateada}_{datetime.now().strftime('%H%M%S')}.xlsx"
        filepath = os.path.join(reports_dir, filename)
        
        # Guardar Excel con formato
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Detecciones', index=False)
            
            # Obtener workbook y worksheet para formato
            workbook = writer.book
            worksheet = writer.sheets['Detecciones']
            
            # Aplicar formato a headers
            from openpyxl.styles import Font, PatternFill, Alignment
            
            header_font = Font(bold=True, color='FFFFFF')
            header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
            
            for cell in worksheet[1]:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = Alignment(horizontal='center')
            
            # Ajustar ancho de columnas
            column_widths = {
                'A': 20, 'B': 15, 'C': 25, 'D': 12, 'E': 12,
                'F': 15, 'G': 12, 'H': 15, 'I': 12, 'J': 10
            }
            
            for col, width in column_widths.items():
                worksheet.column_dimensions[col].width = width
        
        # Calcular tamaño del archivo
        file_size = os.path.getsize(filepath)
        size_mb = round(file_size / (1024 * 1024), 2)
        size_str = f"{size_mb} MB" if size_mb >= 1 else f"{round(file_size / 1024, 1)} KB"
        
        logger.info(f"✅ Excel generado: {filename} ({len(detecciones)} registros)")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'download_url': f'/static/reports/{filename}',
            'registros_incluidos': len(detecciones),
            'fecha': fecha_formateada,
            'tamaño_archivo': size_str,
            'formato': 'excel'
        })
        
    except Exception as e:
        logger.error(f"❌ Error generando Excel día: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/email/send-critical-alert', methods=['POST'])
def send_critical_alert_email():
    """Recibe alertas críticas y envía emails automáticamente"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'})
        
        detection_data = data.get('detection_data', {})
        confidence_score = detection_data.get('confidence_score', 0)
        
        # ✅ VERIFICAR UMBRAL
        if confidence_score < 0.500:
            return jsonify({
                'success': False, 
                'error': f'Score {confidence_score:.3f} por debajo del umbral crítico (0.500)'
            })
        
        # ✅ IMPORTAR SISTEMA DE EMAILS
        try:
            from email_alerts import verificar_y_enviar_alerta_critica
        except ImportError:
            # Si no existe email_alerts.py, crear función básica
            return enviar_email_basico(detection_data)
        
        # ✅ ENVIAR EMAIL USANDO SISTEMA AVANZADO
        success = verificar_y_enviar_alerta_critica(detection_data)
        
        if success:
            # ✅ REGISTRAR ACTIVIDAD
            try:
                registrar_actividad_usuario(
                    data.get('user_id', 1),
                    'critical_email_sent',
                    f"Email crítico enviado: {detection_data.get('source_ip')} (Score: {confidence_score:.3f})",
                    detection_data.get('source_ip', 'unknown')
                )
            except:
                pass  # No fallar si hay error en el registro
            
            logger.info(f"📧 ✅ Email crítico enviado: {detection_data.get('source_ip')} (Score: {confidence_score:.3f})")
            
            return jsonify({
                'success': True,
                'message': 'Email crítico enviado correctamente',
                'details': {
                    'source_ip': detection_data.get('source_ip'),
                    'confidence_score': confidence_score,
                    'anomaly_type': detection_data.get('anomaly_type'),
                    'timestamp': detection_data.get('timestamp')
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Error enviando email crítico',
                'details': {
                    'source_ip': detection_data.get('source_ip'),
                    'confidence_score': confidence_score
                }
            })
            
    except Exception as e:
        logger.error(f"❌ Error en endpoint de email crítico: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

def enviar_email_basico(detection_data):
    """Función básica de email si no está disponible el sistema avanzado"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import datetime
        
        # ✅ CONFIGURACIÓN BÁSICA (CAMBIAR POR TUS DATOS)
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        email_user = 'johannaguinaga20@gmail.com'  # ← TU EMAIL
        email_password = 'TU_CONTRASEÑA_DE_APLICACION'  # ← TU CONTRASEÑA DE APP
        destinatarios = ['johannaguinaga20@gmail.com']  # ← DESTINATARIOS
        
        # ✅ CREAR MENSAJE
        confidence = detection_data.get('confidence_score', 0)
        source_ip = detection_data.get('source_ip', 'Desconocida')
        anomaly_type = detection_data.get('anomaly_type', 'Desconocido')
        
        subject = f"🚨 ALERTA IDS CRÍTICA - {anomaly_type} desde {source_ip}"
        
        body = f"""
🚨 ALERTA CRÍTICA DEL SISTEMA IDS

📊 DETALLES DE LA DETECCIÓN:
• Nivel de Confianza: {confidence:.1%}
• Tipo de Amenaza: {anomaly_type}
• IP de Origen: {source_ip}
• IP de Destino: {detection_data.get('destination_ip', 'N/A')}
• Protocolo: {detection_data.get('protocol', 'N/A')}
• Timestamp: {detection_data.get('timestamp', 'N/A')}

⚠️ ACCIÓN REQUERIDA:
Esta detección ha superado el umbral crítico de confianza (≥ 50%).
Se recomienda investigar inmediatamente esta actividad.

🔗 Sistema IDS Federado
Generado automáticamente el {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
"""
        
        # ✅ CREAR EMAIL
        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = ', '.join(destinatarios)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # ✅ ENVIAR EMAIL
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_user, email_password)
            server.sendmail(email_user, destinatarios, msg.as_string())
        
        logger.info(f"📧 ✅ Email básico enviado: {source_ip} (Score: {confidence:.3f})")
        
        return jsonify({
            'success': True,
            'message': 'Email básico enviado correctamente'
        })
        
    except Exception as e:
        logger.error(f"❌ Error enviando email básico: {e}")
        return jsonify({
            'success': False,
            'error': f'Error email básico: {str(e)}'
        })
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