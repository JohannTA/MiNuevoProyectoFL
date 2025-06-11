-- ========================================
-- BASE DE DATOS IDS FEDERADO - COMPLETA
-- ========================================

-- Eliminar base de datos si existe y crearla nuevamente

-- Habilitar extensiones necesarias
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ========================================
-- TABLAS PRINCIPALES
-- ========================================

-- Tabla de roles
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de permisos
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(150),
    description TEXT,
    module VARCHAR(50) DEFAULT 'general',
    is_system_permission BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de relación roles-permisos (muchos a muchos)
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- Tabla de usuarios
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role_id INTEGER NOT NULL REFERENCES roles(id),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de clientes federados
CREATE TABLE federated_clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    ip_address INET,
    port INTEGER DEFAULT 8080,
    status VARCHAR(20) DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'disconnected', 'error')),
    last_seen TIMESTAMP,
    model_version VARCHAR(50),
    data_samples_count INTEGER DEFAULT 0,
    training_rounds_participated INTEGER DEFAULT 0,
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de modelos ML
CREATE TABLE ml_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    version VARCHAR(50) NOT NULL,
    model_type VARCHAR(50) NOT NULL,
    description TEXT,
    file_path VARCHAR(500),
    model_params JSONB,
    accuracy DECIMAL(5,4),
    training_data_size INTEGER,
    is_active BOOLEAN DEFAULT FALSE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, version)
);

-- Tabla de rondas de entrenamiento federado
CREATE TABLE training_rounds (
    id SERIAL PRIMARY KEY,
    round_number INTEGER NOT NULL,
    model_id INTEGER NOT NULL REFERENCES ml_models(id),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    participants_count INTEGER DEFAULT 0,
    min_participants INTEGER DEFAULT 3,
    max_participants INTEGER DEFAULT 10,
    global_accuracy DECIMAL(5,4),
    aggregation_method VARCHAR(50) DEFAULT 'fedavg',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de participación en rondas
CREATE TABLE round_participation (
    id SERIAL PRIMARY KEY,
    round_id INTEGER NOT NULL REFERENCES training_rounds(id) ON DELETE CASCADE,
    client_id INTEGER NOT NULL REFERENCES federated_clients(id) ON DELETE CASCADE,
    model_update BYTEA,
    local_accuracy DECIMAL(5,4),
    samples_used INTEGER,
    training_time INTEGER, -- en segundos
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(round_id, client_id)
);

-- Tabla de detecciones/anomalías
CREATE TABLE detections (
    id SERIAL PRIMARY KEY,
    detection_id UUID DEFAULT uuid_generate_v4(),
    client_id INTEGER REFERENCES federated_clients(id),
    model_id INTEGER REFERENCES ml_models(id),
    anomaly_type VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence_score DECIMAL(5,4),
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_data JSONB,
    features JSONB,
    is_confirmed BOOLEAN,
    false_positive BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de logs de actividad
CREATE TABLE activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details TEXT,
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de configuración del sistema
CREATE TABLE system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    data_type VARCHAR(20) DEFAULT 'string' CHECK (data_type IN ('string', 'integer', 'boolean', 'json')),
    description TEXT,
    is_system_config BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de notificaciones/alertas
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(20) DEFAULT 'info' CHECK (type IN ('info', 'warning', 'error', 'success')),
    is_read BOOLEAN DEFAULT FALSE,
    detection_id INTEGER REFERENCES detections(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Tabla de sesiones (opcional, para manejo avanzado de sesiones)
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================================
-- ÍNDICES PARA OPTIMIZACIÓN
-- ========================================

-- Índices para usuarios
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX idx_users_is_active ON users(is_active);

-- Índices para clientes federados
CREATE INDEX idx_federated_clients_client_id ON federated_clients(client_id);
CREATE INDEX idx_federated_clients_status ON federated_clients(status);
CREATE INDEX idx_federated_clients_last_seen ON federated_clients(last_seen);

-- Índices para detecciones
CREATE INDEX idx_detections_timestamp ON detections(timestamp);
CREATE INDEX idx_detections_severity ON detections(severity);
CREATE INDEX idx_detections_client_id ON detections(client_id);
CREATE INDEX idx_detections_model_id ON detections(model_id);
CREATE INDEX idx_detections_source_ip ON detections(source_ip);
CREATE INDEX idx_detections_anomaly_type ON detections(anomaly_type);

-- Índices para modelos
CREATE INDEX idx_ml_models_name ON ml_models(name);
CREATE INDEX idx_ml_models_is_active ON ml_models(is_active);
CREATE INDEX idx_ml_models_created_by ON ml_models(created_by);

-- Índices para rondas de entrenamiento
CREATE INDEX idx_training_rounds_model_id ON training_rounds(model_id);
CREATE INDEX idx_training_rounds_status ON training_rounds(status);
CREATE INDEX idx_training_rounds_round_number ON training_rounds(round_number);

-- Índices para logs
CREATE INDEX idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX idx_activity_logs_timestamp ON activity_logs(timestamp);
CREATE INDEX idx_activity_logs_action ON activity_logs(action);

-- Índices para permisos
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Índices para notificaciones
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_is_read ON notifications(is_read);
CREATE INDEX idx_notifications_created_at ON notifications(created_at);

-- ========================================
-- TRIGGERS PARA ACTUALIZACIÓN AUTOMÁTICA
-- ========================================

-- Función para actualizar timestamp de updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Aplicar trigger a todas las tablas que tienen updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_federated_clients_updated_at BEFORE UPDATE ON federated_clients 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ml_models_updated_at BEFORE UPDATE ON ml_models 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_training_rounds_updated_at BEFORE UPDATE ON training_rounds 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_detections_updated_at BEFORE UPDATE ON detections 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger para registrar actividad en cambios de usuario
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details)
        VALUES (NEW.id, 'user_created', 'user', NEW.id, 
                'Usuario creado: ' || NEW.username);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details)
        VALUES (NEW.id, 'user_updated', 'user', NEW.id, 
                'Usuario actualizado: ' || NEW.username);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details)
        VALUES (OLD.id, 'user_deleted', 'user', OLD.id, 
                'Usuario eliminado: ' || OLD.username);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ language 'plpgsql';

CREATE TRIGGER log_user_changes_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION log_user_changes();

-- Trigger para actualizar last_seen en clientes
CREATE OR REPLACE FUNCTION update_client_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE federated_clients 
        SET last_seen = CURRENT_TIMESTAMP 
        WHERE id = NEW.client_id;
    END IF;
    RETURN NULL;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_client_last_seen_trigger
    AFTER INSERT ON detections
    FOR EACH ROW EXECUTE FUNCTION update_client_last_seen();

-- ========================================
-- DATOS INICIALES DEL SISTEMA
-- ========================================

-- Insertar roles del sistema
INSERT INTO roles (name, display_name, description, is_system_role) VALUES
('admin', 'Administrador', 'Acceso completo al sistema', TRUE),
('supervisor', 'Supervisor Principal', 'Supervisión y gestión avanzada', TRUE),
('analyst', 'Analista de Seguridad', 'Análisis de detecciones y reportes', FALSE),
('operator', 'Operador', 'Operaciones básicas del sistema', FALSE),
('viewer', 'Visualizador', 'Solo lectura de dashboards y reportes', FALSE);

-- Insertar permisos del sistema
INSERT INTO permissions (name, display_name, description, module, is_system_permission) VALUES
-- Permisos de administración
('admin_access', 'Acceso de Administrador', 'Acceso completo al panel de administración', 'admin', TRUE),
('manage_users', 'Gestionar Usuarios', 'Crear, editar y eliminar usuarios', 'admin', TRUE),
('manage_roles', 'Gestionar Roles', 'Crear, editar y eliminar roles', 'admin', TRUE),
('manage_permissions', 'Gestionar Permisos', 'Asignar y revocar permisos', 'admin', TRUE),
('manage_system_config', 'Configuración del Sistema', 'Modificar configuración del sistema', 'admin', TRUE),
('view_system_logs', 'Ver Logs del Sistema', 'Acceder a logs de actividad', 'admin', TRUE),

-- Permisos de dashboard
('view_dashboard', 'Ver Dashboard', 'Acceso al dashboard principal', 'dashboard', TRUE),
('view_statistics', 'Ver Estadísticas', 'Acceso a estadísticas del sistema', 'dashboard', FALSE),

-- Permisos de detecciones
('view_detections', 'Ver Detecciones', 'Visualizar detecciones y anomalías', 'detecciones', TRUE),
('manage_detections', 'Gestionar Detecciones', 'Editar y administrar detecciones', 'detecciones', FALSE),
('confirm_detections', 'Confirmar Detecciones', 'Confirmar o marcar como falso positivo', 'detecciones', FALSE),
('export_detections', 'Exportar Detecciones', 'Exportar datos de detecciones', 'detecciones', FALSE),

-- Permisos de clientes
('view_clients', 'Ver Clientes', 'Visualizar clientes federados', 'clientes', TRUE),
('manage_clients', 'Gestionar Clientes', 'Administrar clientes federados', 'clientes', FALSE),
('approve_clients', 'Aprobar Clientes', 'Aprobar nuevos clientes', 'clientes', FALSE),

-- Permisos de modelos
('view_models', 'Ver Modelos', 'Visualizar modelos ML', 'modelos', TRUE),
('manage_models', 'Gestionar Modelos', 'Crear y editar modelos ML', 'modelos', FALSE),
('deploy_models', 'Desplegar Modelos', 'Activar modelos en producción', 'modelos', FALSE),

-- Permisos de reportes
('view_reports', 'Ver Reportes', 'Acceso a reportes del sistema', 'reportes', TRUE),
('create_reports', 'Crear Reportes', 'Generar reportes personalizados', 'reportes', FALSE),
('export_reports', 'Exportar Reportes', 'Exportar reportes en diferentes formatos', 'reportes', FALSE),

-- Permisos de API
('api_access', 'Acceso API', 'Acceder a la API del sistema', 'api', FALSE),
('api_write', 'Escritura API', 'Modificar datos vía API', 'api', FALSE);

-- Asignar permisos a roles
-- Admin: todos los permisos
INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Supervisor: la mayoría de permisos excepto gestión de usuarios/roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT 2, id FROM permissions 
WHERE name NOT IN ('manage_users', 'manage_roles', 'manage_permissions');

-- Analyst: permisos de análisis
INSERT INTO role_permissions (role_id, permission_id)
SELECT 3, id FROM permissions 
WHERE name IN ('view_dashboard', 'view_statistics', 'view_detections', 'manage_detections', 
               'confirm_detections', 'view_clients', 'view_models', 'view_reports', 
               'create_reports', 'export_reports', 'export_detections');

-- Operator: permisos operativos básicos
INSERT INTO role_permissions (role_id, permission_id)
SELECT 4, id FROM permissions 
WHERE name IN ('view_dashboard', 'view_detections', 'view_clients', 'view_models', 'view_reports');

-- Viewer: solo visualización
INSERT INTO role_permissions (role_id, permission_id)
SELECT 5, id FROM permissions 
WHERE name IN ('view_dashboard', 'view_statistics', 'view_detections', 'view_reports');

-- Crear usuario administrador por defecto
INSERT INTO users (username, email, password_hash, first_name, last_name, role_id)
VALUES ('admin', 'admin@ids-federado.com', 
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewrUOscjBGKo3G6e', -- password: admin123
        'Administrador', 'Sistema', 1);

-- Insertar configuración inicial del sistema
INSERT INTO system_config (config_key, config_value, data_type, description, is_system_config) VALUES
('federated_server_host', 'localhost', 'string', 'Host del servidor federado', TRUE),
('federated_server_port', '8080', 'integer', 'Puerto del servidor federado', TRUE),
('aggregation_rounds', '10', 'integer', 'Número de rondas de agregación', FALSE),
('min_clients_per_round', '3', 'integer', 'Mínimo de clientes por ronda', FALSE),
('model_update_interval', '24', 'integer', 'Intervalo de actualización de modelo en horas', FALSE),
('alert_notification_emails', 'admin@ids-federado.com', 'string', 'Emails para notificaciones de alertas', FALSE),
('session_timeout', '8', 'integer', 'Tiempo de expiración de sesión en horas', TRUE),
('max_login_attempts', '5', 'integer', 'Máximo de intentos de login', TRUE),
('force_ssl', 'false', 'boolean', 'Forzar conexiones SSL', TRUE),
('enable_api', 'true', 'boolean', 'Habilitar API REST', FALSE),
('api_token_expiration', '2', 'integer', 'Tiempo de expiración de tokens API en horas', FALSE),
('enable_email_alerts', 'true', 'boolean', 'Habilitar alertas por email', FALSE),
('alert_severity_threshold', 'medium', 'string', 'Umbral de severidad para alertas', FALSE),
('max_alerts_per_hour', '10', 'integer', 'Máximo de alertas por hora', FALSE);

-- Insertar algunos clientes de prueba
INSERT INTO federated_clients (client_id, name, description, ip_address, status, api_key) VALUES
('client_001', 'Cliente Corporativo A', 'Cliente principal del sector financiero', '192.168.1.100', 'active', 'api_key_001'),
('client_002', 'Cliente Gobierno B', 'Organismo gubernamental', '192.168.1.101', 'active', 'api_key_002'),
('client_003', 'Cliente Universidad C', 'Institución educativa', '192.168.1.102', 'inactive', 'api_key_003');

-- Insertar modelo de prueba
INSERT INTO ml_models (name, version, model_type, description, accuracy, training_data_size, is_active, created_by) VALUES
('IDS_Base_Model', '1.0', 'RandomForest', 'Modelo base para detección de intrusiones', 0.9234, 10000, TRUE, 1);

-- Insertar algunas detecciones de prueba
INSERT INTO detections (client_id, model_id, anomaly_type, severity, confidence_score, source_ip, destination_ip, source_port, destination_port, protocol, raw_data) VALUES
(1, 1, 'Port Scan', 'high', 0.95, '192.168.1.200', '192.168.1.100', 12345, 80, 'TCP', '{"packets": 150, "duration": 30}'),
(2, 1, 'DDoS Attack', 'critical', 0.98, '10.0.0.50', '192.168.1.101', 54321, 443, 'TCP', '{"packets": 50000, "duration": 300}'),
(1, 1, 'Unusual Data Transfer', 'medium', 0.75, '192.168.1.100', '8.8.8.8', 443, 443, 'HTTPS', '{"data_size": "2GB", "time": "03:00"}');

-- ========================================
-- VISTAS ÚTILES PARA REPORTES
-- ========================================

-- Vista para estadísticas de usuarios por rol
CREATE VIEW user_role_stats AS
SELECT 
    r.display_name as role_name,
    COUNT(u.id) as user_count,
    COUNT(CASE WHEN u.is_active THEN 1 END) as active_users
FROM roles r
LEFT JOIN users u ON r.id = u.role_id
GROUP BY r.id, r.display_name
ORDER BY user_count DESC;

-- Vista para detecciones por severidad
CREATE VIEW detection_severity_stats AS
SELECT 
    severity,
    COUNT(*) as detection_count,
    AVG(confidence_score) as avg_confidence
FROM detections
WHERE timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
    END;

-- Vista para actividad de clientes
CREATE VIEW client_activity_stats AS
SELECT 
    fc.name as client_name,
    fc.status,
    COUNT(d.id) as total_detections,
    MAX(d.timestamp) as last_detection,
    fc.last_seen
FROM federated_clients fc
LEFT JOIN detections d ON fc.id = d.client_id
GROUP BY fc.id, fc.name, fc.status, fc.last_seen
ORDER BY total_detections DESC;

-- ========================================
-- FUNCIONES ÚTILES
-- ========================================

-- Función para obtener permisos de un usuario
CREATE OR REPLACE FUNCTION get_user_permissions(user_id_param INTEGER)
RETURNS TABLE(permission_name VARCHAR, permission_display_name VARCHAR, module VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT p.name, p.display_name, p.module
    FROM permissions p
    JOIN role_permissions rp ON p.id = rp.permission_id
    JOIN users u ON u.role_id = rp.role_id
    WHERE u.id = user_id_param;
END;
$$ LANGUAGE plpgsql;

-- Función para limpiar logs antiguos
CREATE OR REPLACE FUNCTION cleanup_old_logs(days_to_keep INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM activity_logs 
    WHERE timestamp < CURRENT_DATE - INTERVAL '1 day' * days_to_keep;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Función para obtener estadísticas del dashboard
CREATE OR REPLACE FUNCTION get_dashboard_stats()
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_clients', (SELECT COUNT(*) FROM federated_clients),
        'active_clients', (SELECT COUNT(*) FROM federated_clients WHERE status = 'active'),
        'total_detections', (SELECT COUNT(*) FROM detections),
        'detections_today', (SELECT COUNT(*) FROM detections WHERE DATE(timestamp) = CURRENT_DATE),
        'critical_detections', (SELECT COUNT(*) FROM detections WHERE severity = 'critical' AND timestamp >= CURRENT_DATE - INTERVAL '24 hours'),
        'active_models', (SELECT COUNT(*) FROM ml_models WHERE is_active = TRUE)
    ) INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ========================================
-- COMENTARIOS Y DOCUMENTACIÓN
-- ========================================

COMMENT ON DATABASE ids_federado IS 'Base de datos del Sistema IDS Federado';

COMMENT ON TABLE users IS 'Usuarios del sistema con roles y permisos';
COMMENT ON TABLE roles IS 'Roles del sistema con permisos asociados';
COMMENT ON TABLE permissions IS 'Permisos granulares del sistema';
COMMENT ON TABLE federated_clients IS 'Clientes participantes en el aprendizaje federado';
COMMENT ON TABLE ml_models IS 'Modelos de machine learning entrenados';
COMMENT ON TABLE detections IS 'Detecciones de anomalías e intrusiones';
COMMENT ON TABLE activity_logs IS 'Logs de actividad del sistema';
COMMENT ON TABLE system_config IS 'Configuración del sistema';

-- ========================================
-- GRANTS Y PERMISOS DE BASE DE DATOS
-- ========================================

-- Crear usuario para la aplicación (ajustar según necesidades)
-- CREATE USER ids_app WITH PASSWORD 'secure_password_here';
-- GRANT CONNECT ON DATABASE ids_federado TO ids_app;
-- GRANT USAGE ON SCHEMA public TO ids_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ids_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ids_app;

-- ========================================
-- VERIFICACIÓN FINAL
-- ========================================

-- Verificar que todo se creó correctamente
SELECT 'Tablas creadas: ' || COUNT(*) as info FROM information_schema.tables WHERE table_schema = 'public';
SELECT 'Roles insertados: ' || COUNT(*) as info FROM roles;
SELECT 'Permisos insertados: ' || COUNT(*) as info FROM permissions;
SELECT 'Usuarios creados: ' || COUNT(*) as info FROM users;
SELECT 'Configuraciones insertadas: ' || COUNT(*) as info FROM system_config;

-- Mostrar información de conexión
SELECT 'Base de datos IDS Federado creada exitosamente' as status;
SELECT 'Usuario admin creado - Username: admin, Password: admin123' as default_user;