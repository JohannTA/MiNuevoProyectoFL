# 🗄️ Documentación de Base de Datos: db_tesis

**Fecha de extracción:** 2025-10-04T02:31:05.520383

**PostgreSQL:** PostgreSQL 17.6 on x86_64-windows, compiled by msvc-19.44.35213, 64-bit

## 📊 Resumen

- **Tablas:** 22
- **Vistas:** 3
- **Funciones:** 54
- **Triggers:** 83
- **Índices:** 60

## 📋 Tablas

### 🗂️ activity_logs

**Registros:** 527  
**Tamaño:** 192 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('activity_logs_id_seq'::regclass) | 🔑 PK |
| user_id | integer | ✅ | - | - |
| action | character varying | ❌ | - | - |
| resource_type | character varying | ✅ | - | - |
| resource_id | integer | ✅ | - | - |
| details | text | ✅ | - | - |
| ip_address | inet | ✅ | - | - |
| user_agent | text | ✅ | - | - |
| session_id | character varying | ✅ | - | - |
| timestamp | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `activity_logs_pkey`
- `idx_activity_logs_action`
- `idx_activity_logs_timestamp`
- `idx_activity_logs_user_id`

---

### 🗂️ client_activity_stats

**Registros:** 1  
**Tamaño:** 0 bytes

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| client_name | character varying | ✅ | - | - |
| status | character varying | ✅ | - | - |
| total_detections | bigint | ✅ | - | - |
| last_detection | timestamp without time zone | ✅ | - | - |
| last_seen | timestamp without time zone | ✅ | - | - |

---

### 🗂️ computing_devices

**Registros:** 1  
**Tamaño:** 40 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('computing_devices_id_seq'::regclass) | 🔑 PK |
| type | character varying | ❌ | - | - |
| brand | character varying | ✅ | - | - |
| model | character varying | ✅ | - | - |
| serial_number | character varying | ✅ | - | - |
| assigned_to | integer | ✅ | - | 🔗 FK |
| status | character varying | ✅ | 'active'::character varying | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `assigned_to` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `computing_devices_pkey`
- `computing_devices_serial_number_key`

---

### 🗂️ detection_severity_stats

**Registros:** 3  
**Tamaño:** 0 bytes

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| severity | character varying | ✅ | - | - |
| detection_count | bigint | ✅ | - | - |
| avg_confidence | numeric | ✅ | - | - |

---

### 🗂️ detection_stats

**Registros:** 1  
**Tamaño:** 88 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('detection_stats_id_seq'::regclass) | 🔑 PK |
| total_packets_scanned | integer | ✅ | 0 | - |
| total_detections | integer | ✅ | 0 | - |
| total_suspicious | integer | ✅ | 0 | - |
| total_critical | integer | ✅ | 0 | - |
| total_high | integer | ✅ | 0 | - |
| total_medium | integer | ✅ | 0 | - |
| total_low | integer | ✅ | 0 | - |
| normal_traffic | integer | ✅ | 0 | - |
| last_updated | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| stats_key | character varying | ✅ | 'global_stats'::character varying | - |

#### Índices

- `detection_stats_pkey`
- `detection_stats_stats_key_key`
- `idx_detection_stats_updated`

---

### 🗂️ detections

**Registros:** 9279  
**Tamaño:** 15 MB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('detections_id_seq'::regclass) | 🔑 PK |
| detection_id | uuid | ✅ | uuid_generate_v4() | - |
| client_id | integer | ✅ | - | 🔗 FK |
| model_id | integer | ✅ | - | 🔗 FK |
| anomaly_type | character varying | ✅ | - | - |
| severity | character varying | ✅ | 'medium'::character varying | - |
| confidence_score | numeric | ✅ | - | - |
| source_ip | inet | ✅ | - | - |
| destination_ip | inet | ✅ | - | - |
| source_port | integer | ✅ | - | - |
| destination_port | integer | ✅ | - | - |
| protocol | character varying | ✅ | - | - |
| timestamp | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| raw_data | jsonb | ✅ | - | - |
| features | jsonb | ✅ | - | - |
| is_confirmed | boolean | ✅ | - | - |
| false_positive | boolean | ✅ | false | - |
| notes | text | ✅ | - | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `client_id` → `federated_clients.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION
- `model_id` → `ml_models.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `detections_pkey`
- `idx_detections_anomaly_type`
- `idx_detections_client_id`
- `idx_detections_model_id`
- `idx_detections_severity`
- `idx_detections_source_ip`
- `idx_detections_timestamp`

---

### 🗂️ device_connections

**Registros:** 1  
**Tamaño:** 48 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('device_connections_id_seq'::regclass) | 🔑 PK |
| medical_device_id | integer | ❌ | - | 🔗 FK |
| computing_device_id | integer | ❌ | - | 🔗 FK |
| connected_by | integer | ✅ | - | 🔗 FK |
| connection_date | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| disconnected_date | timestamp without time zone | ✅ | - | - |
| status | character varying | ✅ | 'connected'::character varying | - |
| notes | text | ✅ | - | - |

#### Relaciones (Foreign Keys)

- `computing_device_id` → `computing_devices.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION
- `connected_by` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION
- `medical_device_id` → `medical_devices.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `device_connections_medical_device_id_computing_device_id_key`
- `device_connections_pkey`

---

### 🗂️ federated_clients

**Registros:** 1  
**Tamaño:** 128 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('federated_clients_id_seq'::regclass) | 🔑 PK |
| client_id | character varying | ❌ | - | - |
| name | character varying | ❌ | - | - |
| description | text | ✅ | - | - |
| ip_address | inet | ✅ | - | - |
| port | integer | ✅ | 8080 | - |
| status | character varying | ✅ | 'inactive'::character varying | - |
| last_seen | timestamp without time zone | ✅ | - | - |
| model_version | character varying | ✅ | - | - |
| data_samples_count | integer | ✅ | 0 | - |
| training_rounds_participated | integer | ✅ | 0 | - |
| api_key | character varying | ✅ | - | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `federated_clients_client_id_key`
- `federated_clients_pkey`
- `idx_federated_clients_client_id`
- `idx_federated_clients_last_seen`
- `idx_federated_clients_status`

---

### 🗂️ medical_devices

**Registros:** 1  
**Tamaño:** 48 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('medical_devices_id_seq'::regclass) | 🔑 PK |
| device_type | character varying | ❌ | - | - |
| brand | character varying | ✅ | - | - |
| model | character varying | ✅ | - | - |
| serial_number | character varying | ✅ | - | - |
| location | character varying | ✅ | - | - |
| status | character varying | ✅ | 'active'::character varying | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `medical_devices_pkey`
- `medical_devices_serial_number_key`

---

### 🗂️ ml_models

**Registros:** 1  
**Tamaño:** 96 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('ml_models_id_seq'::regclass) | 🔑 PK |
| name | character varying | ❌ | - | - |
| version | character varying | ❌ | - | - |
| model_type | character varying | ❌ | - | - |
| description | text | ✅ | - | - |
| file_path | character varying | ✅ | - | - |
| model_params | jsonb | ✅ | - | - |
| accuracy | numeric | ✅ | - | - |
| training_data_size | integer | ✅ | - | - |
| is_active | boolean | ✅ | false | - |
| created_by | integer | ✅ | - | 🔗 FK |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `created_by` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `ml_models_name_version_key`
- `ml_models_pkey`
- `idx_ml_models_created_by`
- `idx_ml_models_is_active`
- `idx_ml_models_name`

---

### 🗂️ notifications

**Registros:** 0  
**Tamaño:** 40 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('notifications_id_seq'::regclass) | 🔑 PK |
| user_id | integer | ✅ | - | 🔗 FK |
| title | character varying | ❌ | - | - |
| message | text | ❌ | - | - |
| type | character varying | ✅ | 'info'::character varying | - |
| is_read | boolean | ✅ | false | - |
| detection_id | integer | ✅ | - | 🔗 FK |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| expires_at | timestamp without time zone | ✅ | - | - |

#### Relaciones (Foreign Keys)

- `detection_id` → `detections.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION
- `user_id` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `notifications_pkey`
- `idx_notifications_created_at`
- `idx_notifications_is_read`
- `idx_notifications_user_id`

---

### 🗂️ permissions

**Registros:** 39  
**Tamaño:** 48 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('permissions_id_seq'::regclass) | 🔑 PK |
| name | character varying | ❌ | - | - |
| display_name | character varying | ✅ | - | - |
| description | text | ✅ | - | - |
| module | character varying | ✅ | 'general'::character varying | - |
| is_system_permission | boolean | ✅ | false | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `permissions_name_key`
- `permissions_pkey`

---

### 🗂️ role_permissions

**Registros:** 63  
**Tamaño:** 72 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('role_permissions_id_seq'::regclass) | 🔑 PK |
| role_id | integer | ❌ | - | 🔗 FK |
| permission_id | integer | ❌ | - | 🔗 FK |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `permission_id` → `permissions.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: CASCADE
- `role_id` → `roles.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: CASCADE

#### Índices

- `role_permissions_pkey`
- `role_permissions_role_id_permission_id_key`
- `idx_role_permissions_permission_id`
- `idx_role_permissions_role_id`

---

### 🗂️ roles

**Registros:** 7  
**Tamaño:** 48 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('roles_id_seq'::regclass) | 🔑 PK |
| name | character varying | ❌ | - | - |
| display_name | character varying | ❌ | - | - |
| description | text | ✅ | - | - |
| is_system_role | boolean | ✅ | false | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `roles_name_key`
- `roles_pkey`

---

### 🗂️ round_participation

**Registros:** 0  
**Tamaño:** 24 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('round_participation_id_seq'::regclass) | 🔑 PK |
| round_id | integer | ❌ | - | 🔗 FK |
| client_id | integer | ❌ | - | 🔗 FK |
| model_update | bytea | ✅ | - | - |
| local_accuracy | numeric | ✅ | - | - |
| samples_used | integer | ✅ | - | - |
| training_time | integer | ✅ | - | - |
| submitted_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `client_id` → `federated_clients.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: CASCADE
- `round_id` → `training_rounds.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: CASCADE

#### Índices

- `round_participation_pkey`
- `round_participation_round_id_client_id_key`

---

### 🗂️ system_config

**Registros:** 26  
**Tamaño:** 48 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('system_config_id_seq'::regclass) | 🔑 PK |
| config_key | character varying | ❌ | - | - |
| config_value | text | ✅ | - | - |
| data_type | character varying | ✅ | 'string'::character varying | - |
| description | text | ✅ | - | - |
| is_system_config | boolean | ✅ | false | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Índices

- `system_config_config_key_key`
- `system_config_pkey`

---

### 🗂️ system_configuration

**Registros:** 1  
**Tamaño:** 32 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('system_configuration_id_seq'::regclass) | 🔑 PK |
| federated_server_host | character varying | ✅ | 'localhost'::character varying | - |
| federated_server_port | character varying | ✅ | '8080'::character varying | - |
| aggregation_rounds | integer | ✅ | 10 | - |
| min_clients_per_round | integer | ✅ | 3 | - |
| model_update_interval | integer | ✅ | 24 | - |
| alert_notification_emails | text | ✅ | - | - |
| session_timeout | integer | ✅ | 8 | - |
| max_login_attempts | integer | ✅ | 5 | - |
| force_ssl | boolean | ✅ | false | - |
| enable_api | boolean | ✅ | true | - |
| api_token_expiration | integer | ✅ | 2 | - |
| enable_email_alerts | boolean | ✅ | true | - |
| alert_severity_threshold | character varying | ✅ | 'medium'::character varying | - |
| max_alerts_per_hour | integer | ✅ | 10 | - |
| updated_at | timestamp with time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_by | integer | ✅ | - | 🔗 FK |

#### Relaciones (Foreign Keys)

- `updated_by` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `system_configuration_pkey`

---

### 🗂️ training_rounds

**Registros:** 0  
**Tamaño:** 32 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('training_rounds_id_seq'::regclass) | 🔑 PK |
| round_number | integer | ❌ | - | - |
| model_id | integer | ❌ | - | 🔗 FK |
| status | character varying | ✅ | 'pending'::character varying | - |
| participants_count | integer | ✅ | 0 | - |
| min_participants | integer | ✅ | 3 | - |
| max_participants | integer | ✅ | 10 | - |
| global_accuracy | numeric | ✅ | - | - |
| aggregation_method | character varying | ✅ | 'fedavg'::character varying | - |
| started_at | timestamp without time zone | ✅ | - | - |
| completed_at | timestamp without time zone | ✅ | - | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `model_id` → `ml_models.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `training_rounds_pkey`
- `idx_training_rounds_model_id`
- `idx_training_rounds_round_number`
- `idx_training_rounds_status`

---

### 🗂️ user_role_stats

**Registros:** 7  
**Tamaño:** 0 bytes

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| role_name | character varying | ✅ | - | - |
| user_count | bigint | ✅ | - | - |
| active_users | bigint | ✅ | - | - |

---

### 🗂️ user_sessions

**Registros:** 0  
**Tamaño:** 24 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('user_sessions_id_seq'::regclass) | 🔑 PK |
| user_id | integer | ❌ | - | 🔗 FK |
| session_token | character varying | ❌ | - | - |
| ip_address | inet | ✅ | - | - |
| user_agent | text | ✅ | - | - |
| is_active | boolean | ✅ | true | - |
| last_activity | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| expires_at | timestamp without time zone | ❌ | - | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |

#### Relaciones (Foreign Keys)

- `user_id` → `users.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: CASCADE

#### Índices

- `user_sessions_pkey`
- `user_sessions_session_token_key`

---

### 🗂️ users

**Registros:** 5  
**Tamaño:** 128 kB

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| id | integer | ❌ | nextval('users_id_seq'::regclass) | 🔑 PK |
| username | character varying | ❌ | - | - |
| email | character varying | ❌ | - | - |
| password_hash | character varying | ❌ | - | - |
| first_name | character varying | ✅ | - | - |
| last_name | character varying | ✅ | - | - |
| role_id | integer | ❌ | - | 🔗 FK |
| is_active | boolean | ✅ | true | - |
| last_login | timestamp without time zone | ✅ | - | - |
| failed_login_attempts | integer | ✅ | 0 | - |
| locked_until | timestamp without time zone | ✅ | - | - |
| password_reset_token | character varying | ✅ | - | - |
| password_reset_expires | timestamp without time zone | ✅ | - | - |
| created_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| updated_at | timestamp without time zone | ✅ | CURRENT_TIMESTAMP | - |
| allowed_computing_device_id | integer | ✅ | - | 🔗 FK |

#### Relaciones (Foreign Keys)

- `allowed_computing_device_id` → `computing_devices.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION
- `role_id` → `roles.id`
  - ON UPDATE: NO ACTION
  - ON DELETE: NO ACTION

#### Índices

- `users_email_key`
- `users_pkey`
- `users_username_key`
- `idx_users_email`
- `idx_users_is_active`
- `idx_users_role_id`
- `idx_users_username`

---

### 🗂️ v_normal_traffic

**Registros:** 1  
**Tamaño:** 8192 bytes

#### Columnas

| Columna | Tipo | Nulable | Default | Descripción |
|---------|------|---------|---------|-------------|
| count | bigint | ✅ | - | - |

---

## 👁️ Vistas

### client_activity_stats

```sql
 SELECT fc.name AS client_name,
    fc.status,
    count(d.id) AS total_detections,
    max(d."timestamp") AS last_detection,
    fc.last_seen
   FROM (federated_clients fc
     LEFT JOIN detections d ON ((fc.id = d.client_id)))
  GROUP BY fc.id, fc.name, fc.status, fc.last_seen
  ORDER BY (count(d.id)) DESC;
```

### detection_severity_stats

```sql
 SELECT severity,
    count(*) AS detection_count,
    avg(confidence_score) AS avg_confidence
   FROM detections
  WHERE ("timestamp" >= (CURRENT_DATE - '30 days'::interval))
  GROUP BY severity
  ORDER BY
        CASE severity
            WHEN 'critical'::text THEN 1
            WHEN 'high'::text THEN 2
            WHEN 'medium'::text THEN 3
            WHEN 'low'::text THEN 4
            ELSE NULL::integer
        END;
```

### user_role_stats

```sql
 SELECT r.display_name AS role_name,
    count(u.id) AS user_count,
    count(
        CASE
            WHEN u.is_active THEN 1
            ELSE NULL::integer
        END) AS active_users
   FROM (roles r
     LEFT JOIN users u ON ((r.id = u.role_id)))
  GROUP BY r.id, r.display_name
  ORDER BY (count(u.id)) DESC;
```

## ⚙️ Funciones

### armor

**Argumentos:** `bytea, text[], text[]`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pg_armor
```

### cleanup_old_logs

**Argumentos:** `days_to_keep integer DEFAULT 90`  
**Retorna:** `integer`  
**Lenguaje:** plpgsql

```sql

DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM activity_logs 
    WHERE timestamp < CURRENT_DATE - INTERVAL '1 day' * days_to_keep;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;

```

### crypt

**Argumentos:** `text, text`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pg_crypt
```

### dearmor

**Argumentos:** `text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_dearmor
```

### decrypt

**Argumentos:** `bytea, bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_decrypt
```

### decrypt_iv

**Argumentos:** `bytea, bytea, bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_decrypt_iv
```

### digest

**Argumentos:** `text, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_digest
```

### encrypt

**Argumentos:** `bytea, bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_encrypt
```

### encrypt_iv

**Argumentos:** `bytea, bytea, bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_encrypt_iv
```

### gen_random_bytes

**Argumentos:** `integer`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_random_bytes
```

### gen_random_uuid

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
pg_random_uuid
```

### gen_salt

**Argumentos:** `text, integer`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pg_gen_salt_rounds
```

### get_dashboard_stats

**Argumentos:** ``  
**Retorna:** `json`  
**Lenguaje:** plpgsql

```sql

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

```

### get_user_permissions

**Argumentos:** `user_id_param integer`  
**Retorna:** `TABLE(permission_name character varying, permission_display_name character varying, module character varying)`  
**Lenguaje:** plpgsql

```sql

BEGIN
    RETURN QUERY
    SELECT p.name, p.display_name, p.module
    FROM permissions p
    JOIN role_permissions rp ON p.id = rp.permission_id
    JOIN users u ON u.role_id = rp.role_id
    WHERE u.id = user_id_param;
END;

```

### hmac

**Argumentos:** `text, text, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pg_hmac
```

### log_user_changes

**Argumentos:** ``  
**Retorna:** `trigger`  
**Lenguaje:** plpgsql

```sql

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

```

### pgp_armor_headers

**Argumentos:** `text, OUT key text, OUT value text`  
**Retorna:** `SETOF record`  
**Lenguaje:** c

```sql
pgp_armor_headers
```

### pgp_key_id

**Argumentos:** `bytea`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pgp_key_id_w
```

### pgp_pub_decrypt

**Argumentos:** `bytea, bytea, text, text`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pgp_pub_decrypt_text
```

### pgp_pub_decrypt_bytea

**Argumentos:** `bytea, bytea, text, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_pub_decrypt_bytea
```

### pgp_pub_encrypt

**Argumentos:** `text, bytea`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_pub_encrypt_text
```

### pgp_pub_encrypt_bytea

**Argumentos:** `bytea, bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_pub_encrypt_bytea
```

### pgp_sym_decrypt

**Argumentos:** `bytea, text, text`  
**Retorna:** `text`  
**Lenguaje:** c

```sql
pgp_sym_decrypt_text
```

### pgp_sym_decrypt_bytea

**Argumentos:** `bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_sym_decrypt_bytea
```

### pgp_sym_encrypt

**Argumentos:** `text, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_sym_encrypt_text
```

### pgp_sym_encrypt_bytea

**Argumentos:** `bytea, text`  
**Retorna:** `bytea`  
**Lenguaje:** c

```sql
pgp_sym_encrypt_bytea
```

### recalculate_detection_stats

**Argumentos:** ``  
**Retorna:** `void`  
**Lenguaje:** plpgsql

```sql

DECLARE
    v_total_packets INTEGER;
    v_total_detections INTEGER;
    v_total_suspicious INTEGER;
    v_total_critical INTEGER;
    v_total_high INTEGER;
    v_total_medium INTEGER;
    v_total_low INTEGER;
    v_normal_traffic INTEGER;
BEGIN
    -- Obtener total de paquetes del campo raw_data
    SELECT COALESCE(MAX(CAST(raw_data->>'total_packets_scanned' AS INTEGER)), 0) 
    INTO v_total_packets
    FROM detections 
    WHERE raw_data->>'total_packets_scanned' IS NOT NULL;
    
    -- Total de detecciones (excluyendo tráfico normal)
    SELECT COUNT(*) 
    INTO v_total_detections
    FROM detections 
    WHERE anomaly_type != 'Normal Traffic' 
    AND anomaly_type != 'TOTAL_COUNT';
    
    -- Total sospechosas
    SELECT COUNT(*) 
    INTO v_total_suspicious
    FROM detections 
    WHERE anomaly_type = 'Suspicious Activity';
    
    -- Total críticas
    SELECT COUNT(*) 
    INTO v_total_critical
    FROM detections 
    WHERE severity = 'critical';
    
    -- Total altas
    SELECT COUNT(*) 
    INTO v_total_high
    FROM detections 
    WHERE severity = 'high';
    
    -- Total medias
    SELECT COUNT(*) 
    INTO v_total_medium
    FROM detections 
    WHERE severity = 'medium';
    
    -- Total bajas
    SELECT COUNT(*) 
    INTO v_total_low
    FROM detections 
    WHERE severity = 'low';
    
    -- Tráfico normal
    SELECT COUNT(*) 
    INTO v_normal_traffic
    FROM detections 
    WHERE anomaly_type = 'Normal Traffic';
    
    -- Actualizar o insertar estadísticas
    UPDATE detection_stats SET
        total_packets_scanned = v_total_packets,
        total_detections = v_total_detections,
        total_suspicious = v_total_suspicious,
        total_critical = v_total_critical,
        total_high = v_total_high,
        total_medium = v_total_medium,
        total_low = v_total_low,
        normal_traffic = v_normal_traffic,
        last_updated = CURRENT_TIMESTAMP
    WHERE id = 1;
    
    -- Si no existe el registro, crearlo
    IF NOT FOUND THEN
        INSERT INTO detection_stats (
            total_packets_scanned, total_detections, total_suspicious, total_critical,
            total_high, total_medium, total_low, normal_traffic
        ) VALUES (
            v_total_packets, v_total_detections, v_total_suspicious, v_total_critical,
            v_total_high, v_total_medium, v_total_low, v_normal_traffic
        );
    END IF;
    
    RAISE NOTICE 'Estadísticas recalculadas: % paquetes, % detecciones', 
                 v_total_packets, v_total_detections;
END;

```

### update_client_last_seen

**Argumentos:** ``  
**Retorna:** `trigger`  
**Lenguaje:** plpgsql

```sql

BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE federated_clients 
        SET last_seen = CURRENT_TIMESTAMP 
        WHERE id = NEW.client_id;
    END IF;
    RETURN NULL;
END;

```

### update_detection_stats

**Argumentos:** ``  
**Retorna:** `trigger`  
**Lenguaje:** plpgsql

```sql

BEGIN
    INSERT INTO detection_stats (
        stats_key,
        total_packets_scanned,
        total_detections,
        total_suspicious,
        total_critical,
        total_high,
        total_medium,
        total_low,
        normal_traffic,
        last_updated,
        created_at
    )
    SELECT 
        'global_stats',
        COUNT(*) as total_packets_scanned,
        COUNT(CASE WHEN severity != 'low' OR anomaly_type != 'Normal Traffic' THEN 1 END) as total_detections,
        COUNT(CASE WHEN anomaly_type = 'Suspicious Activity' THEN 1 END) as total_suspicious,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as total_critical,
        COUNT(CASE WHEN severity = 'high' THEN 1 END) as total_high,
        COUNT(CASE WHEN severity = 'medium' THEN 1 END) as total_medium,
        COUNT(CASE WHEN severity = 'low' THEN 1 END) as total_low,
        COUNT(CASE WHEN anomaly_type = 'Normal Traffic' THEN 1 END) as normal_traffic,
        NOW(),
        COALESCE((SELECT created_at FROM detection_stats WHERE stats_key = 'global_stats'), NOW())
    FROM detections
    ON CONFLICT (stats_key) 
    DO UPDATE SET
        total_packets_scanned = EXCLUDED.total_packets_scanned,
        total_detections = EXCLUDED.total_detections,
        total_suspicious = EXCLUDED.total_suspicious,
        total_critical = EXCLUDED.total_critical,
        total_high = EXCLUDED.total_high,
        total_medium = EXCLUDED.total_medium,
        total_low = EXCLUDED.total_low,
        normal_traffic = EXCLUDED.normal_traffic,
        last_updated = NOW();
    
    RETURN NULL;
END;

```

### update_updated_at_column

**Argumentos:** ``  
**Retorna:** `trigger`  
**Lenguaje:** plpgsql

```sql

BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;

```

### uuid_generate_v1

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_generate_v1
```

### uuid_generate_v1mc

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_generate_v1mc
```

### uuid_generate_v3

**Argumentos:** `namespace uuid, name text`  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_generate_v3
```

### uuid_generate_v4

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_generate_v4
```

### uuid_generate_v5

**Argumentos:** `namespace uuid, name text`  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_generate_v5
```

### uuid_nil

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_nil
```

### uuid_ns_dns

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_ns_dns
```

### uuid_ns_oid

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_ns_oid
```

### uuid_ns_url

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_ns_url
```

### uuid_ns_x500

**Argumentos:** ``  
**Retorna:** `uuid`  
**Lenguaje:** c

```sql
uuid_ns_x500
```

## 📊 Diagrama de Entidad-Relación

```mermaid
erDiagram
    computing_devices ||--o{ users : "computing_devices_assigned_to_fkey"
    detections ||--o{ federated_clients : "detections_client_id_fkey"
    detections ||--o{ ml_models : "detections_model_id_fkey"
    device_connections ||--o{ computing_devices : "device_connections_computing_device_id_fkey"
    device_connections ||--o{ users : "device_connections_connected_by_fkey"
    device_connections ||--o{ medical_devices : "device_connections_medical_device_id_fkey"
    ml_models ||--o{ users : "ml_models_created_by_fkey"
    notifications ||--o{ detections : "notifications_detection_id_fkey"
    notifications ||--o{ users : "notifications_user_id_fkey"
    role_permissions ||--o{ permissions : "role_permissions_permission_id_fkey"
    role_permissions ||--o{ roles : "role_permissions_role_id_fkey"
    round_participation ||--o{ federated_clients : "round_participation_client_id_fkey"
    round_participation ||--o{ training_rounds : "round_participation_round_id_fkey"
    system_configuration ||--o{ users : "system_configuration_updated_by_fkey"
    training_rounds ||--o{ ml_models : "training_rounds_model_id_fkey"
    user_sessions ||--o{ users : "user_sessions_user_id_fkey"
    users ||--o{ computing_devices : "users_allowed_computing_device_id_fkey"
    users ||--o{ roles : "users_role_id_fkey"
    activity_logs {
        integer id PK NOT NULL
        integer user_id  NULL
        character varying action  NOT NULL
        character varying resource_type  NULL
        integer resource_id  NULL
        text details  NULL
        inet ip_address  NULL
        text user_agent  NULL
        character varying session_id  NULL
        timestamp without time zone timestamp  NULL
    }
    client_activity_stats {
        character varying client_name  NULL
        character varying status  NULL
        bigint total_detections  NULL
        timestamp without time zone last_detection  NULL
        timestamp without time zone last_seen  NULL
    }
    computing_devices {
        integer id PK NOT NULL
        character varying type  NOT NULL
        character varying brand  NULL
        character varying model  NULL
        character varying serial_number  NULL
        integer assigned_to  NULL
        character varying status  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    detection_severity_stats {
        character varying severity  NULL
        bigint detection_count  NULL
        numeric avg_confidence  NULL
    }
    detection_stats {
        integer id PK NOT NULL
        integer total_packets_scanned  NULL
        integer total_detections  NULL
        integer total_suspicious  NULL
        integer total_critical  NULL
        integer total_high  NULL
        integer total_medium  NULL
        integer total_low  NULL
        integer normal_traffic  NULL
        timestamp without time zone last_updated  NULL
        timestamp without time zone created_at  NULL
        character varying stats_key  NULL
    }
    detections {
        integer id PK NOT NULL
        uuid detection_id  NULL
        integer client_id  NULL
        integer model_id  NULL
        character varying anomaly_type  NULL
        character varying severity  NULL
        numeric confidence_score  NULL
        inet source_ip  NULL
        inet destination_ip  NULL
        integer source_port  NULL
        integer destination_port  NULL
        character varying protocol  NULL
        timestamp without time zone timestamp  NULL
        jsonb raw_data  NULL
        jsonb features  NULL
        boolean is_confirmed  NULL
        boolean false_positive  NULL
        text notes  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    device_connections {
        integer id PK NOT NULL
        integer medical_device_id  NOT NULL
        integer computing_device_id  NOT NULL
        integer connected_by  NULL
        timestamp without time zone connection_date  NULL
        timestamp without time zone disconnected_date  NULL
        character varying status  NULL
        text notes  NULL
    }
    federated_clients {
        integer id PK NOT NULL
        character varying client_id  NOT NULL
        character varying name  NOT NULL
        text description  NULL
        inet ip_address  NULL
        integer port  NULL
        character varying status  NULL
        timestamp without time zone last_seen  NULL
        character varying model_version  NULL
        integer data_samples_count  NULL
        integer training_rounds_participated  NULL
        character varying api_key  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    medical_devices {
        integer id PK NOT NULL
        character varying device_type  NOT NULL
        character varying brand  NULL
        character varying model  NULL
        character varying serial_number  NULL
        character varying location  NULL
        character varying status  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    ml_models {
        integer id PK NOT NULL
        character varying name  NOT NULL
        character varying version  NOT NULL
        character varying model_type  NOT NULL
        text description  NULL
        character varying file_path  NULL
        jsonb model_params  NULL
        numeric accuracy  NULL
        integer training_data_size  NULL
        boolean is_active  NULL
        integer created_by  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    notifications {
        integer id PK NOT NULL
        integer user_id  NULL
        character varying title  NOT NULL
        text message  NOT NULL
        character varying type  NULL
        boolean is_read  NULL
        integer detection_id  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone expires_at  NULL
    }
    permissions {
        integer id PK NOT NULL
        character varying name  NOT NULL
        character varying display_name  NULL
        text description  NULL
        character varying module  NULL
        boolean is_system_permission  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    role_permissions {
        integer id PK NOT NULL
        integer role_id  NOT NULL
        integer permission_id  NOT NULL
        timestamp without time zone created_at  NULL
    }
    roles {
        integer id PK NOT NULL
        character varying name  NOT NULL
        character varying display_name  NOT NULL
        text description  NULL
        boolean is_system_role  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    round_participation {
        integer id PK NOT NULL
        integer round_id  NOT NULL
        integer client_id  NOT NULL
        bytea model_update  NULL
        numeric local_accuracy  NULL
        integer samples_used  NULL
        integer training_time  NULL
        timestamp without time zone submitted_at  NULL
    }
    system_config {
        integer id PK NOT NULL
        character varying config_key  NOT NULL
        text config_value  NULL
        character varying data_type  NULL
        text description  NULL
        boolean is_system_config  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    system_configuration {
        integer id PK NOT NULL
        character varying federated_server_host  NULL
        character varying federated_server_port  NULL
        integer aggregation_rounds  NULL
        integer min_clients_per_round  NULL
        integer model_update_interval  NULL
        text alert_notification_emails  NULL
        integer session_timeout  NULL
        integer max_login_attempts  NULL
        boolean force_ssl  NULL
        boolean enable_api  NULL
        integer api_token_expiration  NULL
        boolean enable_email_alerts  NULL
        character varying alert_severity_threshold  NULL
        integer max_alerts_per_hour  NULL
        timestamp with time zone updated_at  NULL
        integer updated_by  NULL
    }
    training_rounds {
        integer id PK NOT NULL
        integer round_number  NOT NULL
        integer model_id  NOT NULL
        character varying status  NULL
        integer participants_count  NULL
        integer min_participants  NULL
        integer max_participants  NULL
        numeric global_accuracy  NULL
        character varying aggregation_method  NULL
        timestamp without time zone started_at  NULL
        timestamp without time zone completed_at  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
    }
    user_role_stats {
        character varying role_name  NULL
        bigint user_count  NULL
        bigint active_users  NULL
    }
    user_sessions {
        integer id PK NOT NULL
        integer user_id  NOT NULL
        character varying session_token  NOT NULL
        inet ip_address  NULL
        text user_agent  NULL
        boolean is_active  NULL
        timestamp without time zone last_activity  NULL
        timestamp without time zone expires_at  NOT NULL
        timestamp without time zone created_at  NULL
    }
    users {
        integer id PK NOT NULL
        character varying username  NOT NULL
        character varying email  NOT NULL
        character varying password_hash  NOT NULL
        character varying first_name  NULL
        character varying last_name  NULL
        integer role_id  NOT NULL
        boolean is_active  NULL
        timestamp without time zone last_login  NULL
        integer failed_login_attempts  NULL
        timestamp without time zone locked_until  NULL
        character varying password_reset_token  NULL
        timestamp without time zone password_reset_expires  NULL
        timestamp without time zone created_at  NULL
        timestamp without time zone updated_at  NULL
        integer allowed_computing_device_id  NULL
    }
    v_normal_traffic {
        bigint count  NULL
    }
```
