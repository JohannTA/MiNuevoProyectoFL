from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_from_directory
from functools import wraps
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor  # AÑADIR ESTA LÍNEA
import os
import jwt
import datetime
import hashlib
import logging

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
from controladores.controlador_dashboard import obtener_datos_dashboard
from controladores.controlador_sistema import obtener_logs_sistema, obtener_configuracion_sistema, actualizar_configuracion_sistema
from controladores.controlador_roles import (
    obtener_roles, obtener_permisos, obtener_permisos_rol, crear_rol,
    actualizar_rol, eliminar_rol, asignar_permisos_rol, crear_permiso, eliminar_permiso,
    verificar_permiso_usuario, inicializar_permisos_sistema
)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()  # Esto enviará los logs a la consola
    ]
)
logger = logging.getLogger(__name__)
# Configuración para mostrar logs de requests HTTP
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

#---------------------------------------------------------
# Decoradores para protección de rutas
#---------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si el usuario está en sesión
        if 'user_id' not in session:
            flash('Por favor inicie sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Verificar si el token viene en el header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token no proporcionado'}), 401
        
        try:
            # Decodificar el token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
            current_user = obtener_usuario_por_id(user_id)
            
            if not current_user:
                return jsonify({'error': 'Token inválido'}), 401
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

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
                    'exp': datetime.datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
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
# Rutas para detecciones
#---------------------------------------------------------

@app.route('/detecciones')
@login_required
def detecciones():
    # Parámetros de filtrado y paginación
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Filtros desde la URL
    filtros = {
        'client_id': request.args.get('cliente', None, type=int),
        'severity': request.args.get('severidad', None),
        'attack_type': request.args.get('tipo', None),
        'ip': request.args.get('ip', None),
        'fecha_inicio': request.args.get('fecha_inicio', None),
        'fecha_fin': request.args.get('fecha_fin', None),
        'revisado': request.args.get('revisado', None)
    }
    
    # Eliminar filtros vacíos
    filtros = {k: v for k, v in filtros.items() if v is not None}
    
    # Calcular límite y offset para paginación
    offset = (page - 1) * per_page
    
    # Obtener datos
    detecciones_data = obtener_detecciones(limite=per_page, offset=offset, filtros=filtros)
    total_detecciones = obtener_total_detecciones(filtros)
    stats = obtener_estadisticas_detecciones()
    tipos_ataque = obtener_tipos_ataque()
    clientes = obtener_clientes()
    
    # Calcular total de páginas para la paginación
    total_pages = (total_detecciones + per_page - 1) // per_page
    
    # Datos de usuario
    user = obtener_usuario_por_id(session['user_id'])
    
    return render_template('detecciones.html', 
                          user=user, 
                          detecciones=detecciones_data, 
                          stats=stats,
                          tipos_ataque=tipos_ataque,
                          clientes=clientes,
                          filtros=filtros,
                          pagina_actual=page,
                          total_paginas=total_pages,
                          total_detecciones=total_detecciones)

@app.route('/detecciones/<int:deteccion_id>')
@login_required
def deteccion_detalle(deteccion_id):
    user = obtener_usuario_por_id(session['user_id'])
    deteccion = obtener_deteccion_por_id(deteccion_id)
    
    if not deteccion:
        flash('Detección no encontrada', 'danger')
        return redirect(url_for('detecciones'))
    
    return render_template('deteccion_detalle.html', user=user, deteccion=deteccion)

@app.route('/detecciones/exportar')
@login_required
def exportar_detecciones():
    # Obtener filtros
    filtros = {
        'client_id': request.args.get('cliente', None, type=int),
        'severity': request.args.get('severidad', None),
        'attack_type': request.args.get('tipo', None),
        'ip': request.args.get('ip', None),
        'fecha_inicio': request.args.get('fecha_inicio', None),
        'fecha_fin': request.args.get('fecha_fin', None),
        'revisado': request.args.get('revisado', None)
    }
    
    # Eliminar filtros vacíos
    filtros = {k: v for k, v in filtros.items() if v is not None}
    
    # Generar CSV
    csv_path = exportar_reporte_csv('detecciones', filtros)
    
    if csv_path:
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'exportar_detecciones',
            'Exportación de detecciones a CSV',
            request.remote_addr
        )
        return send_from_directory(
            os.path.dirname(csv_path),
            os.path.basename(csv_path),
            as_attachment=True,
            download_name="detecciones_reporte.csv"
        )
    else:
        flash('Error al exportar detecciones', 'danger')
        return redirect(url_for('detecciones'))

#---------------------------------------------------------
# Rutas para clientes federados
#---------------------------------------------------------

@app.route('/clientes')
@login_required
def clientes():
    user = obtener_usuario_por_id(session['user_id'])
    lista_clientes = obtener_clientes()
    
    return render_template('clientes.html', user=user, clientes=lista_clientes)

@app.route('/clientes/<int:cliente_id>')
@login_required
def cliente_detalle(cliente_id):
    user = obtener_usuario_por_id(session['user_id'])
    cliente = obtener_cliente_por_id(cliente_id)
    
    if not cliente:
        flash('Cliente no encontrado', 'danger')
        return redirect(url_for('clientes'))
    
    # Obtener detecciones del cliente
    filtros = {'client_id': cliente_id}
    detecciones = obtener_detecciones(limite=50, filtros=filtros)
    
    return render_template('cliente_detalle.html', user=user, cliente=cliente, detecciones=detecciones)

@app.route('/clientes/nuevo', methods=['POST'])
@admin_required
def crear_cliente_route():
    nombre = request.form.get('nombre')
    ubicacion = request.form.get('ubicacion')
    
    if not nombre:
        flash('El nombre del cliente es obligatorio', 'warning')
        return redirect(url_for('clientes'))
    
    cliente = crear_cliente(nombre, ubicacion)
    
    if cliente:
        flash(f'Cliente {nombre} creado exitosamente', 'success')
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'crear_cliente',
            f'Cliente {nombre} creado',
            request.remote_addr
        )
    else:
        flash('Error al crear el cliente', 'danger')
    
    return redirect(url_for('clientes'))

@app.route('/clientes/<int:cliente_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_cliente_route(cliente_id):
    datos = {
        'name': request.form.get('nombre'),
        'location': request.form.get('ubicacion'),
        'status': request.form.get('estado')
    }
    
    exito = actualizar_cliente(cliente_id, datos)
    
    if exito:
        flash('Cliente actualizado exitosamente', 'success')
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'actualizar_cliente',
            f'Cliente ID {cliente_id} actualizado',
            request.remote_addr
        )
    else:
        flash('Error al actualizar el cliente', 'danger')
    
    return redirect(url_for('cliente_detalle', cliente_id=cliente_id))

@app.route('/clientes/<int:cliente_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_cliente_route(cliente_id):
    exito = eliminar_cliente(cliente_id)
    
    if exito:
        flash('Cliente eliminado exitosamente', 'success')
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'eliminar_cliente',
            f'Cliente ID {cliente_id} eliminado',
            request.remote_addr
        )
    else:
        flash('Error al eliminar el cliente', 'danger')
    
    return redirect(url_for('clientes'))

@app.route('/clientes/<int:cliente_id>/regenerar_key', methods=['POST'])
@admin_required
def regenerar_key_route(cliente_id):
    nueva_key = regenerar_api_key(cliente_id)
    
    if nueva_key:
        flash('API Key regenerada exitosamente', 'success')
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'regenerar_api_key',
            f'API Key regenerada para cliente ID {cliente_id}',
            request.remote_addr
        )
        return jsonify({'success': True, 'api_key': nueva_key})
    else:
        flash('Error al regenerar API Key', 'danger')
        return jsonify({'error': 'No se pudo regenerar la API Key'}), 500

#---------------------------------------------------------
# Rutas para reportes
#---------------------------------------------------------

@app.route('/reportes')
@login_required
def reportes():
    user = obtener_usuario_por_id(session['user_id'])
    tipo = request.args.get('tipo', 'detecciones')
    
    # Filtros para reportes
    filtros = {
        'fecha_inicio': request.args.get('fecha_inicio'),
        'fecha_fin': request.args.get('fecha_fin'),
        'cliente_id': request.args.get('cliente_id', type=int),
        'severidad': request.args.get('severidad'),
        'tipo_ataque': request.args.get('tipo_ataque')
    }
    
    # Eliminar filtros vacíos
    filtros = {k: v for k, v in filtros.items() if v is not None}
    
    # Generar reporte según tipo
    if tipo == 'detecciones':
        reporte = generar_reporte_detecciones(filtros)
    elif tipo == 'clientes':
        reporte = generar_reporte_clientes(filtros)
    elif tipo == 'rendimiento':
        reporte = generar_reporte_rendimiento()
    else:
        reporte = {}
    
    # Obtener lista de clientes para filtros
    clientes = obtener_clientes()
    
    # Obtener tipos de ataque para filtros
    tipos_ataque = obtener_tipos_ataque()
    
    return render_template('reportes.html', 
                          user=user, 
                          tipo=tipo, 
                          reporte=reporte, 
                          filtros=filtros,
                          clientes=clientes,
                          tipos_ataque=tipos_ataque)

@app.route('/reportes/exportar')
@login_required
def exportar_reporte():
    tipo = request.args.get('tipo', 'detecciones')
    
    # Filtros para reportes
    filtros = {
        'fecha_inicio': request.args.get('fecha_inicio'),
        'fecha_fin': request.args.get('fecha_fin'),
        'cliente_id': request.args.get('cliente_id', type=int),
        'severidad': request.args.get('severidad'),
        'tipo_ataque': request.args.get('tipo_ataque')
    }
    
    # Eliminar filtros vacíos
    filtros = {k: v for k, v in filtros.items() if v is not None}
    
    # Generar CSV
    csv_path = exportar_reporte_csv(tipo, filtros)
    
    if csv_path:
        # Registrar actividad
        registrar_actividad_usuario(
            session['user_id'],
            'exportar_reporte',
            f'Exportación de reporte {tipo} a CSV',
            request.remote_addr
        )
        return send_from_directory(
            os.path.dirname(csv_path),
            os.path.basename(csv_path),
            as_attachment=True,
            download_name=f"reporte_{tipo}.csv"
        )
    else:
        flash('Error al exportar reporte', 'danger')
        return redirect(url_for('reportes', tipo=tipo))

#---------------------------------------------------------
# Rutas para administración
#---------------------------------------------------------

@app.route('/admin')
@admin_required
def admin():
    user = obtener_usuario_por_id(session['user_id'])
    
    # Listar usuarios para la pestaña de usuarios
    usuarios = listar_usuarios()
    
    # Obtener roles y permisos
    roles = obtener_roles()
    permisos = obtener_permisos()
    
    # Obtener logs del sistema
    logs = obtener_logs_sistema(limit=100)
    
    # Obtener configuración del sistema
    configuracion = obtener_configuracion_sistema()
    
    return render_template('admin.html', 
                           user=user, 
                           usuarios=usuarios, 
                           roles=roles,
                           permisos=permisos,
                           logs=logs,
                           configuracion=configuracion)

# AGREGAR estas rutas después de exportar_logs() y antes de if __name__ == "__main__":

#---------------------------------------------------------
# Rutas de gestión de usuarios
#---------------------------------------------------------

@app.route('/admin/usuarios/crear', methods=['POST'])
@admin_required
def crear_usuario_route():
    try:
        datos = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'password': request.form.get('password'),
            'role_id': request.form.get('role_id'),
            'is_active': request.form.get('is_active') == 'on'
        }
        
        # Validaciones
        if not datos['username'] or not datos['email'] or not datos['password']:
            flash('Username, email y contraseña son obligatorios', 'danger')
            return redirect(url_for('admin'))
        
        if not datos['role_id']:
            flash('Debe seleccionar un rol', 'danger')
            return redirect(url_for('admin'))
        
        # Crear usuario
        nuevo_id = crear_usuario(datos, session['user_id'])
        
        if nuevo_id:
            flash('Usuario creado exitosamente', 'success')
            registrar_actividad_usuario(
                session['user_id'],
                'crear_usuario',
                f'Usuario {datos["username"]} creado',
                request.remote_addr
            )
        else:
            flash('Error al crear el usuario', 'danger')
            
    except Exception as e:
        logger.error(f"Error en crear_usuario_route: {e}")
        flash('Error interno del servidor', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/usuarios/<int:user_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_usuario_route(user_id):
    try:
        datos = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'role_id': request.form.get('role_id'),
            'is_active': request.form.get('is_active') == 'on'
        }
        
        exito = actualizar_usuario(user_id, datos, session['user_id'])
        
        if exito:
            return jsonify({'success': True, 'message': 'Usuario actualizado exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error al actualizar usuario'})
            
    except Exception as e:
        logger.error(f"Error en actualizar_usuario_route: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'})

@app.route('/admin/usuarios/<int:user_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_usuario_route(user_id):
    try:
        # No permitir eliminar el propio usuario
        if user_id == session['user_id']:
            flash('No puedes eliminar tu propia cuenta', 'danger')
            return redirect(url_for('admin'))
        
        exito = eliminar_usuario(user_id, session['user_id'])
        
        if exito:
            flash('Usuario eliminado exitosamente', 'success')
            registrar_actividad_usuario(
                session['user_id'],
                'eliminar_usuario',
                f'Usuario ID {user_id} eliminado',
                request.remote_addr
            )
        else:
            flash('Error al eliminar el usuario', 'danger')
            
    except Exception as e:
        logger.error(f"Error en eliminar_usuario_route: {e}")
        flash('Error interno del servidor', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/usuarios/<int:user_id>/cambiar-password', methods=['POST'])
@admin_required
def cambiar_password_usuario_route(user_id):
    try:
        nueva_password = request.form.get('nueva_password')
        confirmar_password = request.form.get('confirmar_password')
        
        if not nueva_password or len(nueva_password) < 6:
            return jsonify({'success': False, 'error': 'La contraseña debe tener al menos 6 caracteres'})
        
        if nueva_password != confirmar_password:
            return jsonify({'success': False, 'error': 'Las contraseñas no coinciden'})
        
        # Necesitas implementar esta función en el controlador_usuario
        from controladores.controlador_usuario import cambiar_password_usuario
        exito = cambiar_password_usuario(user_id, nueva_password, session['user_id'])
        
        if exito:
            return jsonify({'success': True, 'message': 'Contraseña actualizada exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error al actualizar contraseña'})
            
    except Exception as e:
        logger.error(f"Error en cambiar_password_usuario_route: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'})

@app.route('/admin/configuracion/actualizar', methods=['POST'])
@admin_required
def actualizar_configuracion_route():
    try:
        configuracion = {
            'federated_server_host': request.form.get('federated_server_host'),
            'federated_server_port': request.form.get('federated_server_port'),
            'aggregation_rounds': request.form.get('aggregation_rounds'),
            'min_clients_per_round': request.form.get('min_clients_per_round'),
            'model_update_interval': request.form.get('model_update_interval'),
            'alert_notification_emails': request.form.get('alert_notification_emails'),
            'session_timeout': request.form.get('session_timeout'),
            'max_login_attempts': request.form.get('max_login_attempts'),
            'force_ssl': request.form.get('force_ssl'),
            'enable_api': request.form.get('enable_api'),
            'api_token_expiration': request.form.get('api_token_expiration'),
            'enable_email_alerts': request.form.get('enable_email_alerts'),
            'alert_severity_threshold': request.form.get('alert_severity_threshold'),
            'max_alerts_per_hour': request.form.get('max_alerts_per_hour')
        }
        
        # Validar campos obligatorios
        campos_requeridos = [
            'federated_server_host', 'federated_server_port', 'aggregation_rounds',
            'min_clients_per_round', 'model_update_interval', 'session_timeout',
            'max_login_attempts', 'api_token_expiration', 'alert_severity_threshold',
            'max_alerts_per_hour'
        ]
        
        for campo in campos_requeridos:
            if not configuracion.get(campo):
                flash(f'El campo {campo.replace("_", " ").title()} es obligatorio', 'warning')
                return redirect(url_for('admin'))
        
        exito = actualizar_configuracion_sistema(configuracion, session['user_id'])
        
        if exito:
            flash('Configuración actualizada exitosamente', 'success')
            registrar_actividad_usuario(
                session['user_id'],
                'actualizar_configuracion',
                'Configuración del sistema actualizada',
                request.remote_addr
            )
        else:
            flash('Error al actualizar la configuración', 'danger')
        
    except Exception as e:
        logger.error(f"Error en actualizar_configuracion_route: {e}")
        flash('Error al procesar la configuración', 'danger')
    
    return redirect(url_for('admin'))

#---------------------------------------------------------
# Rutas para gestión de roles y permisos
#---------------------------------------------------------

@app.route('/admin/roles/nuevo', methods=['POST'])
@admin_required
def crear_rol_route():
    datos = {
        'name': request.form.get('name'),
        'display_name': request.form.get('display_name'),
        'description': request.form.get('description')
    }
    
    if not datos['name'] or not datos['display_name']:
        flash('El nombre y nombre para mostrar son obligatorios', 'warning')
        return redirect(url_for('admin'))
    
    rol = crear_rol(datos['name'], datos['display_name'], datos['description'], session['user_id'])
    
    if rol:
        flash('Rol creado exitosamente', 'success')
    else:
        flash('Error al crear el rol', 'danger')
    
    return redirect(url_for('admin'))

# Reemplazar la ruta actualizar_rol_route existente por esta versión corregida:
@app.route('/admin/roles/<int:role_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_rol_route(role_id):
    try:
        datos = {
            'name': request.form.get('name'),
            'display_name': request.form.get('display_name'),
            'description': request.form.get('description')
        }
        
        if not datos['name'] or not datos['display_name']:
            return jsonify({'success': False, 'error': 'El nombre y nombre para mostrar son obligatorios'})
        
        exito = actualizar_rol(role_id, datos, session['user_id'])
        
        if exito:
            return jsonify({'success': True, 'message': 'Rol actualizado exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error al actualizar el rol'})
            
    except Exception as e:
        logger.error(f"Error en actualizar_rol_route: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'})
@app.route('/admin/roles/<int:role_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_rol_route(role_id):
    exito = eliminar_rol(role_id, session['user_id'])
    
    if exito:
        flash('Rol eliminado exitosamente', 'success')
    else:
        flash('Error al eliminar el rol. Verifique que no tenga usuarios asignados.', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/permisos/nuevo', methods=['POST'])
@admin_required
def crear_permiso_route():
    datos = {
        'name': request.form.get('name'),
        'display_name': request.form.get('display_name'),
        'description': request.form.get('description'),
        'module': request.form.get('module')
    }
    
    if not datos['name'] or not datos['display_name']:
        flash('El nombre y nombre para mostrar son obligatorios', 'warning')
        return redirect(url_for('admin'))
    
    permiso = crear_permiso(
        datos['name'],
        datos['display_name'],
        datos['description'],
        datos['module'],
        session['user_id']
    )
    
    if permiso:
        flash('Permiso creado exitosamente', 'success')
    else:
        flash('Error al crear el permiso', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/roles/<int:role_id>/permisos', methods=['GET', 'POST'])
@admin_required
def gestionar_permisos_rol(role_id):
    if request.method == 'POST':
        try:
            # Obtener permisos seleccionados
            permission_ids = request.form.getlist('permissions')
            permission_ids = [int(pid) for pid in permission_ids if pid.isdigit()]
            
            exito = asignar_permisos_rol(role_id, permission_ids, session['user_id'])
            
            if exito:
                return jsonify({'success': True, 'message': 'Permisos actualizados exitosamente'})
            else:
                return jsonify({'success': False, 'error': 'Error al actualizar permisos'})
                
        except Exception as e:
            logger.error(f"Error al actualizar permisos del rol: {e}")
            return jsonify({'success': False, 'error': 'Error interno del servidor'})
    
    # GET: Devolver permisos del rol
    try:
        permisos_rol = obtener_permisos_rol(role_id)
        todos_permisos = obtener_permisos()
        
        return jsonify({
            'success': True,
            'permisos_rol': [p['id'] for p in permisos_rol],
            'todos_permisos': [dict(p) for p in todos_permisos]
        })
        
    except Exception as e:
        logger.error(f"Error al obtener permisos: {e}")
        return jsonify({'success': False, 'error': 'Error al cargar permisos'})

@app.route('/admin/permisos/<int:permiso_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_permiso_route(permiso_id):
    try:
        datos = {
            'name': request.form.get('name'),
            'display_name': request.form.get('display_name'),
            'description': request.form.get('description'),
            'module': request.form.get('module', 'general')
        }
        
        if not datos['name'] or not datos['display_name']:
            return jsonify({'success': False, 'error': 'Nombre y nombre para mostrar son obligatorios'})
        
        # Actualizar permiso usando el controlador
        from controladores.controlador_roles import actualizar_permiso
        exito = actualizar_permiso(permiso_id, datos, session['user_id'])
        
        if exito:
            return jsonify({'success': True, 'message': 'Permiso actualizado exitosamente'})
        else:
            return jsonify({'success': False, 'error': 'Error al actualizar el permiso'})
            
    except Exception as e:
        logger.error(f"Error en actualizar_permiso_route: {e}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'})


# Agregar esta ruta después de la ruta actualizar_permiso_route:
@app.route('/admin/permisos/<int:permiso_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_permiso_route(permiso_id):
    try:
        exito = eliminar_permiso(permiso_id, session['user_id'])
        
        if exito:
            flash('Permiso eliminado exitosamente', 'success')
            registrar_actividad_usuario(
                session['user_id'],
                'eliminar_permiso',
                f'Permiso ID {permiso_id} eliminado',
                request.remote_addr
            )
        else:
            flash('Error al eliminar el permiso. Verifique que no esté asignado a ningún rol.', 'danger')
        
    except Exception as e:
        logger.error(f"Error en eliminar_permiso_route: {e}")
        flash('Error interno del servidor', 'danger')
    
    return redirect(url_for('admin'))

#---------------------------------------------------------
# Rutas de API
#---------------------------------------------------------

@app.route('/api/detecciones/<int:deteccion_id>', methods=['POST'])
@token_required
def actualizar_deteccion_api(current_user, deteccion_id):
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No se proporcionaron datos'}), 400
    
    # Extraer datos
    revisado = data.get('revisado')
    notas = data.get('notas')
    
    # Actualizar
    exito = actualizar_deteccion(
        deteccion_id=deteccion_id,
        revisado=revisado,
        notas=notas,
        usuario_id=current_user['id']
    )
    
    if exito:
        # Registrar actividad
        registrar_actividad_usuario(
            current_user['id'],
            'actualizar_deteccion',
            f'Detección {deteccion_id} actualizada',
            request.remote_addr
        )
        return jsonify({'success': True, 'message': 'Detección actualizada correctamente'})
    else:
        return jsonify({'error': 'Error al actualizar la detección'}), 500

@app.route('/api/token', methods=['POST'])
def get_token():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Se requiere usuario y contraseña'}), 400
    
    # Autenticar usando el controlador
    user_data = autenticar_usuario(username, password)
    
    if not user_data:
        return jsonify({'error': 'Credenciales inválidas'}), 401
    
    token_payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'exp': datetime.datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
    }
    token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    
    # Registrar actividad
    registrar_actividad_usuario(
        user_data['id'],
        'api_token',
        'Generación de token API',
        request.remote_addr
    )
    
    return jsonify({
        'token': token,
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role']
    })

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user):
    try:
        # Obtener estadísticas actualizadas del dashboard
        datos_dashboard = obtener_datos_dashboard()
        
        # Formatear respuesta para API
        response = {
            'success': True,
            'data': datos_dashboard,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error en API dashboard stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener estadísticas del dashboard'
        }), 500

@app.route('/api/dashboard/stats/simple', methods=['GET'])
@login_required  # Para requests desde la web app
def get_dashboard_stats_simple():
    try:
        datos_dashboard = obtener_datos_dashboard()
        
        # Simplificar datos para actualización rápida
        stats_simple = {
            'total_detecciones': datos_dashboard.get('resumen', {}).get('total_detecciones', 0),
            'detecciones_24h': datos_dashboard.get('resumen', {}).get('detecciones_24h', 0),
            'pendientes_revision': datos_dashboard.get('resumen', {}).get('pendientes_revision', 0),
            'clientes_activos': datos_dashboard.get('resumen', {}).get('clientes_activos', 0),
            'alertas_criticas': datos_dashboard.get('resumen', {}).get('alertas_criticas', 0)
        }
        
        return jsonify({
            'success': True,
            'stats': stats_simple,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error en API dashboard stats simple: {e}")
        return jsonify({
            'success': False,
            'error': 'Error al obtener estadísticas'
        }), 500

@app.route('/api/detecciones', methods=['GET'])
@token_required
def get_detecciones_api(current_user):
    # Parámetros de filtrado y paginación
    limite = request.args.get('limite', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    # Filtros
    filtros = {
        'client_id': request.args.get('cliente', None, type=int),
        'severity': request.args.get('severidad', None),
        'attack_type': request.args.get('tipo', None),
        'ip': request.args.get('ip', None),
        'fecha_inicio': request.args.get('fecha_inicio', None),
        'fecha_fin': request.args.get('fecha_fin', None),
        'revisado': request.args.get('revisado', None)
    }
    
    # Eliminar filtros vacíos
    filtros = {k: v for k, v in filtros.items() if v is not None}
    
    # Obtener datos
    detecciones = obtener_detecciones(limite=limite, offset=offset, filtros=filtros)
    total = obtener_total_detecciones(filtros)
    
    return jsonify({
        'detecciones': detecciones,
        'total': total,
        'limite': limite,
        'offset': offset
    })

@app.route('/api/clientes', methods=['GET'])
@token_required
def get_clientes_api(current_user):
    clientes = obtener_clientes()
    return jsonify(clientes)

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

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

#---------------------------------------------------------
# Rutas de desarrollo/debug (solo disponibles en modo debug)
#---------------------------------------------------------

@app.route('/verificar_hash/<username>/<password>')
def verificar_hash(username, password):
    # Esta ruta solo debe estar disponible en entorno de desarrollo
    if not app.debug:
        return "Acceso no permitido", 403
    
    conn = None
    try:
        # Generar hash de la contraseña proporcionada
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        conn = obtener_conexion()
        if not conn:
            return jsonify({"error": "No se pudo conectar a la base de datos"}), 500
        
        from psycopg2.extras import RealDictCursor
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Buscar el usuario
            cursor.execute("SELECT username, password_hash FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({
                    "mensaje": f"Usuario {username} no encontrado",
                    "hash_generado": password_hash
                }), 404
            
            # Comparar hashes
            coincide = user['password_hash'] == password_hash
            
            return jsonify({
                "usuario": user['username'],
                "hash_generado": password_hash,
                "hash_almacenado": user['password_hash'],
                "coinciden": coincide,
                "mensaje": "Contraseña correcta" if coincide else "Contraseña incorrecta"
            })
    except Exception as e:
        logger.error(f"Error al verificar hash: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

#---------------------------------------------------------
# Inicialización de la aplicación
#---------------------------------------------------------
@app.route('/admin/logs/buscar')
@admin_required
def buscar_logs():
    query = request.args.get('q', '')
    usuario_filtro = request.args.get('usuario', '')
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    
    filtros = {}
    if usuario_filtro:
        filtros['usuario'] = usuario_filtro
    if fecha_inicio:
        filtros['fecha_inicio'] = fecha_inicio
    if fecha_fin:
        filtros['fecha_fin'] = fecha_fin
    if query:
        filtros['accion'] = query
    
    logs = obtener_logs_sistema(limit=50, filtros=filtros)
    
    return jsonify({
        'logs': logs,
        'total': len(logs)
    })

@app.route('/admin/logs/exportar')
@admin_required
def exportar_logs():
    import csv
    import io
    from datetime import datetime
    from flask import make_response
    
    try:
        # Obtener filtros de los parámetros de la URL
        filtros = {}
        
        usuario_filtro = request.args.get('usuario', '').strip()
        if usuario_filtro:
            filtros['usuario'] = usuario_filtro
            
        fecha_inicio = request.args.get('fecha_inicio', '').strip()
        if fecha_inicio:
            filtros['fecha_inicio'] = fecha_inicio
            
        fecha_fin = request.args.get('fecha_fin', '').strip()
        if fecha_fin:
            filtros['fecha_fin'] = fecha_fin
            
        accion_filtro = request.args.get('accion', '').strip()
        if accion_filtro:
            filtros['accion'] = accion_filtro
        
        # Obtener logs del sistema usando el controlador
        logs = obtener_logs_sistema(limit=10000, filtros=filtros)
        
        if not logs:
            # Si no hay logs, crear CSV vacío con headers
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Fecha/Hora', 'Usuario', 'Acción', 'Detalles', 'IP'])
            writer.writerow(['', '', '', 'No hay logs para exportar', '', ''])
        else:
            # Crear CSV en memoria
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Escribir cabecera
            writer.writerow(['ID', 'Fecha/Hora', 'Usuario', 'Acción', 'Detalles', 'IP'])
            
            # Escribir datos
            for log in logs:
                writer.writerow([
                    log.get('id', ''),
                    str(log.get('timestamp', '')),
                    log.get('username', 'Sistema'),
                    log.get('message', log.get('action', '')),
                    log.get('details', ''),
                    log.get('ip_address', '')
                ])
        
        # Preparar el contenido del CSV
        csv_content = output.getvalue()
        output.close()
        
        # Crear respuesta HTTP con el CSV
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="logs_sistema_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        # Registrar la actividad de exportación
        registrar_actividad_usuario(
            session['user_id'],
            'exportar_logs',
            'Exportación de logs del sistema a CSV',
            request.remote_addr
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error al exportar logs: {e}")
        flash('Error al exportar logs del sistema', 'danger')
        return redirect(url_for('admin'))

# Filtros personalizados para Jinja2
@app.template_filter('number_format')
def number_format_filter(value):
    """Formatea números con separadores de miles"""
    try:
        return f"{value:,}"
    except (ValueError, TypeError):
        return value

@app.template_filter('percentage')
def percentage_filter(value, decimals=1):
    """Convierte a porcentaje"""
    try:
        return f"{value * 100:.{decimals}f}%"
    except (ValueError, TypeError):
        return "0%"

@app.template_filter('time_ago')
def time_ago_filter(datetime_obj):
    """Muestra tiempo transcurrido desde una fecha"""
    if not datetime_obj:
        return "Nunca"
    
    try:
        from datetime import datetime
        now = datetime.now()
        diff = now - datetime_obj
        
        if diff.days > 0:
            return f"Hace {diff.days} día{'s' if diff.days > 1 else ''}"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"Hace {hours} hora{'s' if hours > 1 else ''}"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"Hace {minutes} minuto{'s' if minutes > 1 else ''}"
        else:
            return "Hace unos segundos"
    except:
        return "Tiempo desconocido"

# Agregar después de las otras rutas API:

from actualizador_tiempo_real import actualizador_tiempo_real

@app.route('/api/realtime/stats')
@login_required
def get_realtime_stats():
    """Obtiene estadísticas en tiempo real para el dashboard"""
    try:
        stats = actualizador_tiempo_real.get_real_time_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error en stats tiempo real: {e}")
        return jsonify({'error': 'Error obteniendo estadísticas'}), 500

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
                SELECT d.*, fc.name as client_name
                FROM detections d
                LEFT JOIN federated_clients fc ON d.client_id = fc.id
                ORDER BY d.timestamp DESC
                LIMIT %s
            """, (limit,))
            
            detections = [dict(row) for row in cursor.fetchall()]
            
            # Formatear timestamps
            for detection in detections:
                if detection['timestamp']:
                    detection['timestamp'] = detection['timestamp'].isoformat()
            
        conn.close()
        return jsonify({'detections': detections})
        
    except Exception as e:
        logger.error(f"Error obteniendo detecciones tiempo real: {e}")
        return jsonify({'error': 'Error interno'}), 500

if __name__ == "__main__":
    # Verificar existencia de directorios necesarios
    for dir_path in ['static', 'static/css', 'static/js', 'static/img', 'uploads']:
        full_path = os.path.join(app.root_path, dir_path)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
            logger.info(f"Directorio creado: {full_path}")
    
    # Iniciar la aplicación
    logger.info("Iniciando aplicación IDS Federado...")
    app.run(host='0.0.0.0', port=5000, debug=True)