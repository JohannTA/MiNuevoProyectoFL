from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, send_from_directory
import os
import jwt
import datetime
import hashlib
from functools import wraps
from db.db import obtener_conexion
# Evitar importaciones duplicadas
from controladores.controlador_usuario import (
    obtener_usuario_por_id, autenticar_usuario, registrar_actividad_usuario, 
    listar_usuarios, crear_usuario, actualizar_usuario, eliminar_usuario
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

import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',  # Añadir archivo de log
    filemode='a'
)
logger = logging.getLogger(__name__)

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

# Decorador para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si el usuario está en sesión
        if 'user_id' not in session:
            flash('Por favor inicie sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')

# Decorador para verificar rol de administrador
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

# Decorador para verificar rol de supervisor
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

# Ruta principal - Dashboard
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Obtener datos necesarios para el dashboard
    user = obtener_usuario_por_id(session['user_id'])
    datos_dashboard = obtener_datos_dashboard()
    
    return render_template('dashboard.html', user=user, datos=datos_dashboard)

# Ruta para detecciones/alertas
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

# Detalle de una detección
@app.route('/detecciones/<int:deteccion_id>')
@login_required
def deteccion_detalle(deteccion_id):
    user = obtener_usuario_por_id(session['user_id'])
    deteccion = obtener_deteccion_por_id(deteccion_id)
    
    if not deteccion:
        flash('Detección no encontrada', 'danger')
        return redirect(url_for('detecciones'))
    
    return render_template('deteccion_detalle.html', user=user, deteccion=deteccion)

# Exportar detecciones a CSV
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

# Actualizar estado de una detección (AJAX)
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

# Ruta para clientes federados
@app.route('/clientes')
@login_required
def clientes():
    user = obtener_usuario_por_id(session['user_id'])
    lista_clientes = obtener_clientes()
    
    return render_template('clientes.html', user=user, clientes=lista_clientes)

# Detalle de un cliente
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

# Crear cliente (solo admin)
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

# Actualizar cliente (solo admin)
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

# Eliminar cliente (solo admin)
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

# Regenerar API Key (solo admin)
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

# Ruta para reportes
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

# Exportar reportes a CSV
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

# Ruta para administración (solo para admins)
@app.route('/admin')
@admin_required
def admin():
    user = obtener_usuario_por_id(session['user_id'])
    
    # Listar usuarios para la pestaña de usuarios
    usuarios = listar_usuarios()
    
    # Obtener logs del sistema
    logs = obtener_logs_sistema(limit=100)
    
    # Obtener configuración del sistema
    configuracion = obtener_configuracion_sistema()
    
    return render_template('admin.html', 
                           user=user, 
                           usuarios=usuarios, 
                           logs=logs,
                           configuracion=configuracion)

# Administración de usuarios
@app.route('/admin/usuarios/nuevo', methods=['POST'])
@admin_required
def crear_usuario_route():
    datos = {
        'username': request.form.get('username'),
        'email': request.form.get('email'),
        'password': request.form.get('password'),
        'role_id': request.form.get('role_id', type=int),
        'first_name': request.form.get('first_name'),
        'last_name': request.form.get('last_name')
    }
    
    if not datos['username'] or not datos['email'] or not datos['password'] or not datos['role_id']:
        flash('Todos los campos obligatorios deben ser completados', 'warning')
        return redirect(url_for('admin'))
    
    usuario = crear_usuario(datos, session['user_id'])
    
    if usuario:
        flash('Usuario creado exitosamente', 'success')
        registrar_actividad_usuario(
            session['user_id'],
            'crear_usuario',
            f'Usuario {datos["username"]} creado',
            request.remote_addr
        )
    else:
        flash('Error al crear el usuario', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/usuarios/<int:usuario_id>/actualizar', methods=['POST'])
@admin_required
def actualizar_usuario_route(usuario_id):
    datos = {
        'username': request.form.get('username'),
        'email': request.form.get('email'),
        'role_id': request.form.get('role_id', type=int),
        'first_name': request.form.get('first_name'),
        'last_name': request.form.get('last_name'),
        'is_active': request.form.get('is_active') == 'on'
    }
    
    # Si se proporciona una nueva contraseña, incluirla
    password = request.form.get('password')
    if password:
        datos['password'] = password
    
    exito = actualizar_usuario(usuario_id, datos, session['user_id'])
    
    if exito:
        flash('Usuario actualizado exitosamente', 'success')
        registrar_actividad_usuario(
            session['user_id'],
            'actualizar_usuario',
            f'Usuario ID {usuario_id} actualizado',
            request.remote_addr
        )
    else:
        flash('Error al actualizar el usuario', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/usuarios/<int:usuario_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_usuario_route(usuario_id):
    # Evitar que un usuario se elimine a sí mismo
    if usuario_id == session['user_id']:
        flash('No puede eliminar su propio usuario', 'warning')
        return redirect(url_for('admin'))
    
    exito = eliminar_usuario(usuario_id)
    
    if exito:
        flash('Usuario eliminado exitosamente', 'success')
        registrar_actividad_usuario(
            session['user_id'],
            'eliminar_usuario',
            f'Usuario ID {usuario_id} eliminado',
            request.remote_addr
        )
    else:
        flash('Error al eliminar el usuario', 'danger')
    
    return redirect(url_for('admin'))

# Configuración del sistema
@app.route('/admin/configuracion/actualizar', methods=['POST'])
@admin_required
def actualizar_configuracion_route():
    configuracion = {
        'federated_server_host': request.form.get('federated_server_host'),
        'federated_server_port': request.form.get('federated_server_port'),
        'aggregation_rounds': request.form.get('aggregation_rounds'),
        'min_clients_per_round': request.form.get('min_clients_per_round'),
        'model_update_interval': request.form.get('model_update_interval'),
        'alert_notification_emails': request.form.get('alert_notification_emails')
    }
    
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
    
    return redirect(url_for('admin'))

# API para obtener token JWT
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

# Middleware para la API que verifica token JWT
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

# API de ejemplo protegida con JWT
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user):
    # Obtener estadísticas reales del dashboard
    datos_dashboard = obtener_datos_dashboard()
    return jsonify(datos_dashboard)

# API para obtener detecciones
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

# API para obtener clientes
@app.route('/api/clientes', methods=['GET'])
@token_required
def get_clientes_api(current_user):
    clientes = obtener_clientes()
    return jsonify(clientes)

# Manejador de errores 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Manejador de errores 500
@app.errorhandler(500)
def server_error(e):
    logger.error(f"Error 500: {str(e)}")
    return render_template('500.html'), 500

# Manejador de errores 403
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# Ruta para cambiar contraseña de usuario
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
    
    # Implementar cambio de contraseña (debes crear esta función en el controlador)
    from controladores.controlador_usuario import cambiar_contrasena_usuario
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

# Ruta para verificar manualmente hash (solo para desarrollo)
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

if __name__ == '__main__':
    # Verificar existencia de directorios necesarios
    for dir_path in ['static', 'static/css', 'static/js', 'static/img', 'uploads']:
        full_path = os.path.join(app.root_path, dir_path)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
            logger.info(f"Directorio creado: {full_path}")
    
    # Iniciar la aplicación
    logger.info("Iniciando aplicación IDS Federado...")
    app.run(debug=True, host='0.0.0.0', port=5000)