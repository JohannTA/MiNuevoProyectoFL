-- Crear la base de datos
-- Ejecutar esto como superusuario
-- CREATE DATABASE ids_federado;

-- Usar la base de datos
-- \c ids_federado

-- Extensiones útiles
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tabla de roles
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(30) NOT NULL UNIQUE,
    display_name VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insertar los 3 roles solicitados
INSERT INTO roles (name, display_name, description)
VALUES 
    ('admin', 'Administrador', 'Control total del sistema'),
    ('supervisor', 'Supervisor', 'Monitoreo y análisis de alertas'),
    ('asistente', 'Asistente', 'Visualización sin modificación (solo lectura)');

-- Tabla de permisos
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

-- Insertar permisos básicos
INSERT INTO permissions (name, description)
VALUES 
    ('view_dashboard', 'Ver el dashboard principal'),
    ('manage_users', 'Administrar usuarios'),
    ('view_clients', 'Ver clientes federados'),
    ('manage_clients', 'Administrar clientes federados'),
    ('view_detections', 'Ver detecciones'),
    ('review_detections', 'Revisar y clasificar detecciones'),
    ('view_reports', 'Ver reportes'),
    ('manage_settings', 'Administrar configuración del sistema'),
    ('manage_models', 'Administrar modelos federados');

-- Tabla de relación roles-permisos
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Asignar permisos a roles
-- Admin: todos los permisos
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name = 'admin'),
    id
FROM permissions;

-- Supervisor: permisos de visualización y revisión
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name = 'supervisor'),
    id
FROM permissions 
WHERE name IN ('view_dashboard', 'view_clients', 'view_detections', 'review_detections', 'view_reports');

-- Asistente: solo visualización (solo lectura)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name = 'asistente'),
    id
FROM permissions 
WHERE name IN ('view_dashboard', 'view_clients', 'view_detections', 'view_reports');

-- Tabla de usuarios
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    password_reset_token VARCHAR(100),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    remember_token VARCHAR(100),
    api_key VARCHAR(64) UNIQUE,
    updated_by INTEGER REFERENCES users(id)
);

-- Tabla de sesiones
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Tabla de clientes federados
CREATE TABLE federated_clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    location VARCHAR(200),
    interface VARCHAR(50),
    ip_address VARCHAR(45),
    version VARCHAR(20),
    
    -- Estado de conexión
    status VARCHAR(20) DEFAULT 'disconnected',
    connected_at TIMESTAMP WITH TIME ZONE,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    last_stats_update TIMESTAMP WITH TIME ZONE,
    
    -- Estadísticas
    total_packets BIGINT DEFAULT 0,
    total_flows BIGINT DEFAULT 0,
    total_alerts BIGINT DEFAULT 0,
    
    -- Modelo federado
    model_version INTEGER DEFAULT 0,
    last_model_update TIMESTAMP WITH TIME ZONE,
    
    -- Datos adicionales
    client_key VARCHAR(100) UNIQUE,
    description TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de detecciones (alertas)
CREATE TABLE detections (
    id SERIAL PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES federated_clients(id),
    
    -- Información de la detección
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    
    -- Clasificación
    attack_type VARCHAR(50) NOT NULL,
    confidence_score FLOAT NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- normal, suspicious, attack
    
    -- Detalles adicionales
    packet_size INTEGER,
    flow_duration FLOAT,
    flags VARCHAR(50),
    
    -- Metadatos
    model_version INTEGER,
    processing_time FLOAT,
    raw_features TEXT,
    
    -- Estado
    reviewed BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    notes TEXT,
    
    -- Auditoría
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- Índices para mejorar consultas frecuentes
CREATE INDEX idx_detections_timestamp ON detections(timestamp);
CREATE INDEX idx_detections_client_id ON detections(client_id);
CREATE INDEX idx_detections_severity ON detections(severity);
CREATE INDEX idx_detections_attack_type ON detections(attack_type);
CREATE INDEX idx_detections_src_ip ON detections(src_ip);
CREATE INDEX idx_detections_dst_ip ON detections(dst_ip);

-- Tabla para modelos federados
CREATE TABLE federated_models (
    id SERIAL PRIMARY KEY,
    version INTEGER NOT NULL,
    round_number INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Información del modelo
    participating_clients INTEGER,
    accuracy FLOAT,
    loss FLOAT,
    
    -- Archivo del modelo
    model_path VARCHAR(255),
    model_size BIGINT,  -- en bytes
    
    -- Metadatos
    aggregation_method VARCHAR(50),
    training_data_size INTEGER,
    features_count INTEGER,
    
    is_active BOOLEAN DEFAULT FALSE,
    created_by INTEGER REFERENCES users(id),
    
    UNIQUE(version, round_number)
);

-- Tabla para estadísticas de clientes
CREATE TABLE client_stats (
    id SERIAL PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES federated_clients(id),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Métricas
    cpu_usage FLOAT,
    memory_usage FLOAT,
    network_in_bytes BIGINT,
    network_out_bytes BIGINT,
    packets_per_second INTEGER,
    flows_per_second INTEGER,
    alerts_per_minute INTEGER,
    
    -- Estadísticas del modelo local
    model_version INTEGER,
    local_accuracy FLOAT,
    training_time FLOAT
);

CREATE INDEX idx_client_stats_timestamp ON client_stats(timestamp);
CREATE INDEX idx_client_stats_client_id ON client_stats(client_id);

-- Tabla de logs del sistema
CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),  -- users, clients, detections, etc.
    entity_id VARCHAR(100),   -- ID del objeto afectado
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_system_logs_timestamp ON system_logs(timestamp);
CREATE INDEX idx_system_logs_user_id ON system_logs(user_id);
CREATE INDEX idx_system_logs_action ON system_logs(action);
CREATE INDEX idx_system_logs_entity ON system_logs(entity_type, entity_id);

-- Tabla para configuración del sistema
CREATE TABLE system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id)
);

-- Insertar configuraciones iniciales
INSERT INTO system_settings (key, value, description, is_sensitive)
VALUES 
    ('federated_server_host', '0.0.0.0', 'Host para el servidor federado', false),
    ('federated_server_port', '5000', 'Puerto para el servidor federado', false),
    ('aggregation_rounds', '3', 'Número de rondas para la agregación federada', false),
    ('min_clients_per_round', '2', 'Mínimo de clientes por ronda de agregación', false),
    ('model_update_interval', '86400', 'Intervalo de actualización del modelo (segundos)', false),
    ('alert_notification_emails', '', 'Emails para notificaciones (separados por comas)', false),
    ('password_min_length', '8', 'Longitud mínima de contraseña', false),
    ('password_require_uppercase', 'true', 'Requerir mayúsculas en contraseñas', false),
    ('password_require_special', 'true', 'Requerir caracteres especiales en contraseñas', false),
    ('max_login_attempts', '5', 'Intentos máximos de login antes de bloqueo', false),
    ('account_lockout_duration', '1800', 'Duración del bloqueo de cuenta en segundos', false);

-- Vista para estadísticas de detecciones por día
CREATE VIEW daily_detection_stats AS
SELECT 
    DATE_TRUNC('day', timestamp) AS day,
    severity,
    COUNT(*) AS count
FROM detections
GROUP BY DATE_TRUNC('day', timestamp), severity
ORDER BY day DESC, severity;

-- Vista para estadísticas de clientes activos
CREATE VIEW active_clients AS
SELECT 
    c.id,
    c.name,
    c.location,
    c.status,
    c.connected_at,
    c.last_heartbeat,
    c.total_alerts,
    CASE 
        WHEN c.last_heartbeat > NOW() - INTERVAL '2 minutes' THEN true
        ELSE false
    END AS is_online,
    CASE 
        WHEN c.connected_at IS NOT NULL THEN AGE(NOW(), c.connected_at)
        ELSE NULL
    END AS uptime
FROM federated_clients c
WHERE c.last_heartbeat > NOW() - INTERVAL '24 hours';

-- Vista para usuarios con roles
CREATE VIEW user_roles_view AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.is_active,
    r.name AS role_name,
    r.display_name AS role_display_name,
    u.last_login
FROM 
    users u
JOIN 
    roles r ON u.role_id = r.id;

-- Funciones y triggers para auditoría de cambios

-- Función para registrar cambios en usuarios (corregida)
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO system_logs(user_id, action, entity_type, entity_id, details, ip_address)
    VALUES (
        CASE
            WHEN TG_OP = 'UPDATE' AND NEW.updated_by IS NOT NULL THEN NEW.updated_by
            ELSE NULL
        END,
        CASE 
            WHEN TG_OP = 'INSERT' THEN 'user_created'
            WHEN TG_OP = 'UPDATE' THEN 'user_updated'
            WHEN TG_OP = 'DELETE' THEN 'user_deleted'
        END,
        'users',
        CASE
            WHEN TG_OP = 'DELETE' THEN OLD.id::text
            ELSE NEW.id::text
        END,
        CASE
            WHEN TG_OP = 'INSERT' THEN 'Nuevo usuario: ' || NEW.username
            WHEN TG_OP = 'UPDATE' THEN 'Actualización de usuario: ' || NEW.username
            WHEN TG_OP = 'DELETE' THEN 'Eliminación de usuario: ' || OLD.username
        END,
        '127.0.0.1'  -- Esto se actualizará desde la aplicación
    );
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Creación del trigger (sin intentar eliminarlo primero)
CREATE TRIGGER user_audit_trigger
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION log_user_changes();

-- Función para actualizar last_update en settings
CREATE OR REPLACE FUNCTION update_settings_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER settings_timestamp_trigger
BEFORE UPDATE ON system_settings
FOR EACH ROW EXECUTE FUNCTION update_settings_timestamp();

-- Función para la autenticación de usuarios
CREATE OR REPLACE FUNCTION authenticate_user(p_username VARCHAR, p_password VARCHAR)
RETURNS TABLE (
    user_id INTEGER,
    username VARCHAR,
    role_name VARCHAR,
    role_display_name VARCHAR,
    is_authenticated BOOLEAN,
    error_message VARCHAR
) AS $$
DECLARE
    v_user users%ROWTYPE;
    v_role roles%ROWTYPE;
    v_max_attempts INTEGER;
    v_lockout_duration INTEGER;
BEGIN
    -- Obtener configuración de intentos de login
    SELECT COALESCE(value::integer, 5) INTO v_max_attempts
    FROM system_settings WHERE key = 'max_login_attempts';
    
    SELECT COALESCE(value::integer, 1800) INTO v_lockout_duration
    FROM system_settings WHERE key = 'account_lockout_duration';
    
    -- Verificar si existe el usuario
    SELECT * INTO v_user FROM users WHERE username = p_username;
    
    IF v_user.id IS NULL THEN
        RETURN QUERY SELECT NULL::integer, NULL::varchar, NULL::varchar, NULL::varchar, false, 'Usuario no encontrado';
        RETURN;
    END IF;
    
    -- Verificar si la cuenta está bloqueada
    IF v_user.account_locked_until IS NOT NULL AND v_user.account_locked_until > NOW() THEN
        RETURN QUERY SELECT v_user.id, v_user.username, NULL::varchar, NULL::varchar, false, 
            'Cuenta bloqueada. Inténtelo de nuevo más tarde.';
        RETURN;
    END IF;
    
    -- Verificar si la cuenta está activa
    IF NOT v_user.is_active THEN
        RETURN QUERY SELECT v_user.id, v_user.username, NULL::varchar, NULL::varchar, false, 'Cuenta desactivada';
        RETURN;
    END IF;
    
    -- Verificar contraseña
    IF crypt(p_password, v_user.password_hash) = v_user.password_hash THEN
        -- Contraseña correcta, resetear contador de intentos
        UPDATE users 
        SET failed_login_attempts = 0, 
            last_login = NOW(), 
            account_locked_until = NULL
        WHERE id = v_user.id;
        
        -- Obtener información del rol
        SELECT * INTO v_role FROM roles WHERE id = v_user.role_id;
        
        RETURN QUERY SELECT v_user.id, v_user.username, v_role.name, v_role.display_name, true, NULL::varchar;
        
        -- Registrar inicio de sesión exitoso
        INSERT INTO system_logs(user_id, action, entity_type, entity_id, details)
        VALUES (v_user.id, 'login_success', 'users', v_user.id::text, 'Inicio de sesión exitoso');
        
    ELSE
        -- Contraseña incorrecta, incrementar contador de intentos
        UPDATE users 
        SET failed_login_attempts = failed_login_attempts + 1,
            account_locked_until = CASE 
                WHEN failed_login_attempts + 1 >= v_max_attempts THEN NOW() + (v_lockout_duration * INTERVAL '1 second')
                ELSE NULL
              END
        WHERE id = v_user.id;
        
        -- Registrar intento fallido
        INSERT INTO system_logs(user_id, action, entity_type, entity_id, details)
        VALUES (v_user.id, 'login_failed', 'users', v_user.id::text, 'Intento de inicio de sesión fallido');
        
        IF v_user.failed_login_attempts + 1 >= v_max_attempts THEN
            RETURN QUERY SELECT v_user.id, v_user.username, NULL::varchar, NULL::varchar, false, 
                'Demasiados intentos fallidos. Su cuenta ha sido bloqueada temporalmente.';
        ELSE
            RETURN QUERY SELECT v_user.id, v_user.username, NULL::varchar, NULL::varchar, false, 
                'Contraseña incorrecta. Intentos restantes: ' || (v_max_attempts - (v_user.failed_login_attempts + 1));
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Función para verificar permisos de usuario
CREATE OR REPLACE FUNCTION user_has_permission(p_user_id INTEGER, p_permission_name VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    has_permission BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM users u
        JOIN roles r ON u.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = p_user_id AND p.name = p_permission_name
    ) INTO has_permission;
    
    RETURN has_permission;
END;
$$ LANGUAGE plpgsql;

-- Insertar usuarios por defecto con roles
INSERT INTO users (username, email, password_hash, role_id, first_name, last_name)
VALUES 
    ('admin', 'admin@ids-federado.com', 
     crypt('admin123', gen_salt('bf')), 
     (SELECT id FROM roles WHERE name = 'admin'),
     'Administrador', 'Sistema'),
    ('supervisor', 'supervisor@ids-federado.com',
     crypt('supervisor123', gen_salt('bf')), 
     (SELECT id FROM roles WHERE name = 'supervisor'),
     'Supervisor', 'Principal'),
    ('asistente', 'asistente@ids-federado.com',
     crypt('asistente123', gen_salt('bf')), 
     (SELECT id FROM roles WHERE name = 'asistente'),
     'Asistente', 'Lectura');