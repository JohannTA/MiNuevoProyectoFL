import pyshark
import time
import joblib
import pandas as pd
import socket
from collections import defaultdict

# ==== Cargar paquete de modelo ====
paquete = joblib.load('model/paquete_modelo_flows.pkl')
modelo = paquete['modelo']
scaler = paquete['scaler']
encoders = paquete['encoders']
columnas = paquete['columnas']
num_cols = paquete['num_cols']
cat_cols = paquete['cat_cols']

# === Motor de reglas avanzado (con motivos de detección) ===
def motor_reglas_flujo(flujo):
    # Reglas originales mejoradas con motivos
    if flujo['count'] > 100 and flujo['duration'] < 10:
        return True, "Alto volumen de paquetes en poco tiempo"
    if flujo['bytes'] > 50000 and flujo['count'] < 10:
        return True, "Paquetes grandes con baja frecuencia"
        
    # Detección de ataques de alta frecuencia (SYN flood, nping, etc.)
    if flujo['proto'] == 'tcp' and flujo['count'] > 30 and flujo['duration'] < 3:
        return True, "Posible TCP flood o escaneo intensivo"
        
    # Detección de tasas de paquete anormalmente altas
    if flujo['duration'] > 0.1:  # Evitar división por cero
        pkt_rate = flujo['count'] / flujo['duration']
        if pkt_rate > 30 and flujo['count'] > 20:
            return True, f"Tasa de paquetes anormalmente alta: {pkt_rate:.1f} pkt/s"
            
    # Detección de conexiones fallidas repetidas
    if flujo.get('conn_state', '') == 'REJ' and flujo['count'] > 5:
        return True, "Múltiples conexiones rechazadas"
        
    # Escaneo de puertos
    if flujo.get('dst_ports_unique', 0) > 10 and flujo['count'] > 15:
        return True, "Posible escaneo de puertos (múltiples destinos)"
        
    # Anomalía en tamaño de paquetes
    avg_bytes_per_packet = flujo['bytes'] / flujo['count'] if flujo['count'] > 0 else 0
    if avg_bytes_per_packet < 20 and flujo['count'] > 30:
        return True, "Paquetes pequeños repetitivos, posible reconocimiento"
        
    return False, ""

# === Preprocesamiento con diagnóstico ===
def preprocesar_flujo_vector(flujo, debug=False):
    """Preprocesa un flujo para pasarlo al modelo con diagnóstico"""
    # Crear un DataFrame con todas las columnas esperadas por el modelo
    flujo_adaptado = pd.DataFrame(columns=columnas)
    
    # Añadir una fila con valores predeterminados
    flujo_adaptado.loc[0] = 0
    
    # Rellenar con los valores del flujo actual
    flujo_adaptado['proto'][0] = flujo.get('proto', 'unknown')
    flujo_adaptado['service'][0] = flujo.get('service', 'unknown')
    flujo_adaptado['conn_state'][0] = flujo.get('conn_state', 'unknown')
    flujo_adaptado['dns_qtype'][0] = flujo.get('dns_qtype', 0)
    flujo_adaptado['http_status_code'][0] = flujo.get('http_status_code', 0)
    flujo_adaptado['type'][0] = 'normal'
    flujo_adaptado['flujo_count'][0] = flujo.get('count', 0)
    flujo_adaptado['duration_sum'][0] = flujo.get('duration', 0)
    flujo_adaptado['src_bytes_sum'][0] = flujo.get('src_bytes', 0)
    flujo_adaptado['dst_bytes_sum'][0] = flujo.get('dst_bytes', 0)
    flujo_adaptado['src_pkts_sum'][0] = flujo.get('src_pkts_sum', flujo.get('count', 0))
    flujo_adaptado['dst_pkts_sum'][0] = flujo.get('dst_pkts_sum', 0)
    
    if debug:
        print(">>> DIAGNÓSTICO DE PREPROCESAMIENTO <<<")
        print(f"Flujo original: {flujo}")
        print(f"Columnas del DataFrame: {flujo_adaptado.columns.tolist()}")
        print(f"Columnas esperadas por el modelo: {columnas}")
        print(f"Columnas categóricas: {cat_cols}")
        print(f"Columnas numéricas: {num_cols}")
    
    # Mapeo seguro de estados de conexión
    conn_state_map = {
        'EST': 'ESTAB',
        'REJ': 'RSTO',
        'SYN': 'S0',
        'UNK': 'OTH'
    }
    
    # Aplicar mapeos seguros para categorías conocidas
    if 'conn_state' in conn_state_map:
        if flujo_adaptado['conn_state'][0] in conn_state_map:
            flujo_adaptado.loc[0, 'conn_state'] = conn_state_map[flujo_adaptado['conn_state'][0]]
    
    # Codifica categóricas con manejo de valores desconocidos
    X_encoded = flujo_adaptado.copy()
    
    for col in cat_cols:
        if col in encoders:
            try:
                encoder = encoders[col]
                if hasattr(encoder, 'categories_'):
                    categories = encoder.categories_[0]
                    
                    if debug:
                        print(f"\nPara columna '{col}':")
                        print(f"  - Valor actual: '{flujo_adaptado[col][0]}'")
                        print(f"  - Categorías conocidas: {categories}")
                    
                    # Verificar si el valor actual no está en las categorías conocidas
                    if str(flujo_adaptado[col][0]) not in categories:
                        if debug:
                            print(f"  - ADVERTENCIA: Valor '{flujo_adaptado[col][0]}' no está en categorías conocidas.")
                            print(f"  - Usando '{categories[0]}' como alternativa.")
                        flujo_adaptado.loc[0, col] = categories[0]
                
                # Codificar solo la columna actual
                col_encoded = encoder.transform(flujo_adaptado[[col]].astype(str))
                X_encoded[col] = col_encoded
                
                if debug:
                    print(f"  - Valor codificado: {X_encoded[col][0]}")
            except Exception as e:
                if debug:
                    print(f"ERROR al codificar '{col}': {str(e)}")
                X_encoded[col] = 0
    
    # Escalado con manejo de errores
    try:
        # Crear un nuevo DataFrame solo con las columnas numéricas
        numeric_df = X_encoded[num_cols].copy()
        scaled_values = scaler.transform(numeric_df)
        X_encoded[num_cols] = scaled_values
        
        if debug:
            print("Escalado completado con éxito")
    except Exception as e:
        if debug:
            print(f"ERROR en escalado: {e}")
            
    return X_encoded

def detector_flujo(flujo, debug=False):
    """Detecta si un flujo es anómalo utilizando modelo híbrido"""
    # Diagnosticar un flujo aleatorio de vez en cuando
    if debug or (hash(str(flujo)) % 100 == 1):  # Diagnosticar ~1% de los flujos
        df_flujo = preprocesar_flujo_vector(flujo, debug=True)
    else:
        df_flujo = preprocesar_flujo_vector(flujo)
    
    # Predicción con manejo de errores
    try:
        proba_array = modelo.predict_proba(df_flujo)
        if debug:
            print(f"Matriz de probabilidad: {proba_array}")
        
        if proba_array.shape[1] >= 2:
            proba = proba_array[0, 1]  # Clase positiva (ataque)
        else:
            proba = 0.5  # No podemos determinar, usamos valor neutral
            if debug:
                print("ADVERTENCIA: Formato de probabilidad inesperado")
    except Exception as e:
        if debug:
            print(f"ERROR en predicción: {e}")
        proba = 0.5
    
    # Verificación basada en reglas
    regla_activada, motivo = motor_reglas_flujo(flujo)
    
    # Umbrales para el detector híbrido
    THRESH_LOWER = 0.25  # Más bajo para aumentar sensibilidad
    THRESH_UPPER = 0.55
    
    # Modo híbrido: combinando ML y reglas
    if proba > THRESH_UPPER:
        return '🚨 ATAQUE (ML)', proba, None
    elif regla_activada:
        if proba > THRESH_LOWER:  # Confirmado por ML y reglas
            return f'🚨 ATAQUE CONFIRMADO (HÍBRIDO)', proba, motivo
        else:  # Solo detectado por reglas
            return f'🚨 ANOMALÍA (REGLA)', proba, motivo
    else:
        if proba < THRESH_LOWER:
            return '✅ NORMAL', proba, None
        else:
            return '⚠️ SOSPECHOSO (ML)', proba, "Probabilidad media sin reglas activadas"

# ==== PyShark captura flujos ====
TIMEOUT_FLOW = 10  # segundos de inactividad para cerrar el flujo
flows = {}

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def get_flow_key(pkt):
    try:
        ip = pkt.ip
        src_ip = ip.src
        dst_ip = ip.dst
        proto = pkt.transport_layer
        layer = getattr(pkt, proto.lower(), None)
        src_port = getattr(layer, 'srcport', 0) if layer else 0
        dst_port = getattr(layer, 'dstport', 0) if layer else 0
        return (src_ip, src_port, dst_ip, dst_port, proto)
    except Exception:
        return None

def process_flow(key, flow):
    # Extrae información del flujo
    src_ip, src_port, dst_ip, dst_port, proto = key
    
    # Analiza el estado de la conexión si es TCP
    conn_state = flow.get('conn_state', 'desconocido')
    
    # Prepara las características para el modelo con nombres adaptados
    flujo_features = {
        'proto': proto.lower() if proto else 'desconocido',
        'service': str(flow.get('service', 'desconocido')),
        'conn_state': conn_state, 
        'dns_qtype': 0,
        'http_status_code': 0,
        'type': 'normal',  # Valor por defecto seguro
        'flujo_count': flow['count'],
        'duration_sum': flow['duration'],
        'src_bytes_sum': flow['src_bytes'],
        'dst_bytes_sum': flow['dst_bytes'],
        'src_pkts_sum': flow['count'],
        'dst_pkts_sum': 0,
        # Estos campos son para las reglas y no para el modelo
        'count': flow['count'],
        'duration': flow['duration'],
        'bytes': flow['bytes'],
        'dst_ports_unique': flow.get('dst_ports_unique', 0)
    }
    
    resultado, prob, motivo = detector_flujo(flujo_features)
    
    # Formato de salida mejorado
    src_name = resolve_hostname(src_ip) if src_ip != '127.0.0.1' else 'localhost'
    dst_name = resolve_hostname(dst_ip) if dst_ip != '127.0.0.1' else 'localhost'
    
    flow_info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})"
    
    if motivo:
        print(f"[{resultado}] {flow_info} | Prob: {prob:.2f} | {motivo} | Paquetes: {flow['count']} | Bytes: {flow['bytes']} | Duración: {flow['duration']:.2f}s")
    else:
        print(f"[{resultado}] {flow_info} | Prob: {prob:.2f} | Paquetes: {flow['count']} | Bytes: {flow['bytes']} | Duración: {flow['duration']:.2f}s")

def validar_modelo():
    """Valida el modelo con ejemplos conocidos para diagnosticar problemas"""
    print("\n=== VALIDACIÓN DEL MODELO ===")
    
    # Ejemplos de flujos para prueba (adaptados al formato esperado)
    flujos_prueba = [
        {
            'proto': 'tcp',
            'service': 'http', 
            'conn_state': 'ESTAB',  # Usar directamente la categoría conocida
            'dns_qtype': 0,
            'http_status_code': 0,
            'type': 'normal',
            'flujo_count': 5,
            'duration_sum': 2.5,
            'src_bytes_sum': 500,
            'dst_bytes_sum': 5000,
            'src_pkts_sum': 5,
            'dst_pkts_sum': 10,
            # Para reglas
            'count': 5,
            'duration': 2.5,
            'bytes': 5500,
            'dst_ports_unique': 1,
        },
        {
            'proto': 'tcp',
            'service': 'http',
            'conn_state': 'RSTO',  # Usar directamente la categoría conocida
            'dns_qtype': 0, 
            'http_status_code': 0,
            'type': 'normal',
            'flujo_count': 50,
            'duration_sum': 1.0,
            'src_bytes_sum': 3000,
            'dst_bytes_sum': 0,
            'src_pkts_sum': 50,
            'dst_pkts_sum': 0,
            # Para reglas
            'count': 50, 
            'duration': 1.0,
            'bytes': 3000,
            'dst_ports_unique': 20,
        },
        # Un flujo extremo para ver si el modelo puede detectarlo
        {
            'proto': 'tcp',
            'service': 'http',
            'conn_state': 'S0',
            'dns_qtype': 0, 
            'http_status_code': 0,
            'type': 'normal',
            'flujo_count': 500,
            'duration_sum': 0.5,
            'src_bytes_sum': 30000,
            'dst_bytes_sum': 0,
            'src_pkts_sum': 500,
            'dst_pkts_sum': 0,
            # Para reglas
            'count': 500,
            'duration': 0.5,
            'bytes': 30000,
            'dst_ports_unique': 50,
        }
    ]
    
    # Probar con cada flujo
    for i, flujo in enumerate(flujos_prueba):
        print(f"\n--- Flujo de prueba #{i+1} ---")
        resultado, prob, motivo = detector_flujo(flujo, debug=True)
        print(f"Resultado: {resultado}")
        print(f"Probabilidad: {prob}")
        if motivo:
            print(f"Motivo: {motivo}")
    
    print("\n=== FIN VALIDACIÓN ===\n")

def main():
    print("Sistema de detección de intrusiones basado en flujos de red")
    print("========================================================")
    print("Interfaces de red (elige tu alias/índice):")
    import psutil
    net_if_addrs = psutil.net_if_addrs()
    interfaces = list(net_if_addrs.keys())
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    selected_idx = int(input("Selecciona el número de la interfaz que deseas usar: "))
    interface = interfaces[selected_idx]
    print(f"Escuchando en {interface}... Ctrl+C para salir.")
    print("========================================================")

    # Estadísticas agregadas por IP de origen
    ip_src_stats = defaultdict(lambda: {
        'total_packets': 0,
        'unique_ports': set(),
        'start_time': time.time(),
        'flows': 0
    })
    
    # Rastreo de puertos únicos por par IP origen/destino
    target_tracking = defaultdict(set)

    # Iniciar captura
    cap = pyshark.LiveCapture(interface=interface)
    for pkt in cap.sniff_continuamente():
        now = time.time()
        key = get_flow_key(pkt)
        if key is None:
            continue
            
        src_ip, src_port, dst_ip, dst_port, proto = key
        length = int(getattr(pkt, 'length', 0))
        
        # Actualizar seguimiento de puertos únicos
        if dst_port != '0':
            flow_id = (src_ip, dst_ip)
            target_tracking[flow_id].add(dst_port)
            dst_ports_unique = len(target_tracking[flow_id])
        else:
            dst_ports_unique = 0
            
        # Detectar estado de conexión TCP
        conn_state = 'UNK'
        if proto == 'TCP' and hasattr(pkt.tcp, 'flags'):
            flags = pkt.tcp.flags
            if '0x0002' in flags:  # SYN
                conn_state = 'SYN'
            elif '0x0014' in flags:  # RST+ACK
                conn_state = 'REJ'
            elif '0x0010' in flags:  # ACK
                conn_state = 'EST'

        # Inicializa o actualiza el flujo
        if key not in flows:
            flows[key] = {
                'start': now,
                'end': now,
                'count': 1,
                'bytes': length,
                'src_bytes': length,
                'dst_bytes': 0,
                'duration': 0,
                'conn_state': conn_state,
                'dst_ports_unique': dst_ports_unique,
                'service': dst_port
            }
        else:
            flows[key]['end'] = now
            flows[key]['count'] += 1
            flows[key]['bytes'] += length
            flows[key]['src_bytes'] += length
            flows[key]['duration'] = flows[key]['end'] - flows[key]['start']
            flows[key]['dst_ports_unique'] = dst_ports_unique
            # Actualizar estado de conexión si es más significativo
            if conn_state in ['REJ', 'EST'] and flows[key]['conn_state'] not in ['REJ', 'EST']:
                flows[key]['conn_state'] = conn_state
        
        # Actualizar estadísticas por IP de origen (para detección agregada)
        ip_src_stats[src_ip]['total_packets'] += 1
        if dst_port != '0':
            ip_src_stats[src_ip]['unique_ports'].add(dst_port)
        
        # Analizar comportamiento agregado por IP
        window = 5.0  # segundos para analizar
        if now - ip_src_stats[src_ip]['start_time'] >= window:
            packets_per_sec = ip_src_stats[src_ip]['total_packets'] / window
            unique_ports = len(ip_src_stats[src_ip]['unique_ports'])
            
            # Detección de escaneo TCP intensivo o inundación
            if proto == 'TCP' and packets_per_sec > 50 and ip_src_stats[src_ip]['total_packets'] > 100:
                if unique_ports <= 3:
                    print(f"[🚨 ALERTA SISTEMA] Posible ataque de inundación TCP desde {src_ip} ({packets_per_sec:.1f} pkt/s)")
                else:
                    print(f"[🚨 ALERTA SISTEMA] Posible escaneo de puertos desde {src_ip} ({unique_ports} puertos, {packets_per_sec:.1f} pkt/s)")
            
            # Reiniciar estadísticas para siguiente ventana
            ip_src_stats[src_ip] = {
                'total_packets': 0,
                'unique_ports': set(),
                'start_time': now,
                'flows': 0
            }

        # Cierra flujos inactivos
        expired = []
        for k, f in flows.items():
            if now - f['end'] > TIMEOUT_FLOW:
                process_flow(k, f)
                expired.append(k)
        for k in expired:
            del flows[k]

if __name__ == "__main__":
    try:
        # Validar el modelo primero
        validar_modelo()
        
        # Preguntar si continuar después de validación
        respuesta = input("\n¿Continuar con la detección en vivo? (s/n): ")
        if respuesta.lower() != 's':
            print("Detector cancelado.")
            exit()
            
        main()
    except KeyboardInterrupt:
        print("\nDetector detenido por el usuario.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()