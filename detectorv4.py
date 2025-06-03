import pyshark
import time
import joblib
import numpy as np
import socket
import csv
import os
from datetime import datetime

# 1. Carga modelo y preprocesador
MODEL_DIR = 'model'  # Ajusta según donde tengas los .pkl
model = joblib.load(f'{MODEL_DIR}/modelo_rf.pkl')
pre = joblib.load(f'{MODEL_DIR}/preprocesamiento.pkl')
features = pre['features']
scaler = pre['scaler']

# 2. Parámetros de flujo
FLOW_TIMEOUT = 30  # Segundos de inactividad para cerrar un flujo
INTERFACE = 'Wi-Fi'  # Cambia por tu interfaz, ej: 'Wi-Fi' en Windows

# 2.1. Configuración del logger
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
LOG_FILE = f"{LOG_DIR}/ataques_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# Crear archivo de log con encabezados
with open(LOG_FILE, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 
                    'duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
                    'bytes_per_sec', 'pkts_per_sec', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
                    'confianza'])

# 3. Estructura para flujos activos
flujos = {}

def get_flow_key(pkt):
    try:
        proto = pkt.transport_layer
        return (
            pkt.ip.src,
            pkt[pkt.transport_layer].srcport,
            pkt.ip.dst,
            pkt[pkt.transport_layer].dstport,
            proto
        )
    except Exception:
        return None

def log_attack(key, data, confianza):
    """Registra un ataque detectado en el archivo de log"""
    src_ip, src_port, dst_ip, dst_port, proto = key
    
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            src_ip, src_port, dst_ip, dst_port, proto,
            data['duration'],
            data['fwd_packets'],
            data['bwd_packets'],
            data['fwd_bytes'],
            data['bwd_bytes'],
            data['bytes_per_sec'],
            data['pkts_per_sec'],
            data['fwd_pkt_len_mean'],
            data['bwd_pkt_len_mean'],
            confianza
        ])
    
    print(f"🚨 ALERTA: Ataque registrado en {LOG_FILE}")

def process_flow(key, data):
    # Calcula features y predice
    feats = []
    feats.append(data['duration'])  # Flow Duration
    feats.append(data['fwd_packets'])  # Total Fwd Packets
    feats.append(data['bwd_packets'])  # Total Backward Packets
    feats.append(data['fwd_bytes'])  # Total Length of Fwd Packets
    feats.append(data['bwd_bytes'])  # Total Length of Bwd Packets
    feats.append(data['bytes_per_sec'])  # Flow Bytes/s
    feats.append(data['pkts_per_sec'])  # Flow Packets/s
    feats.append(data['fwd_pkt_len_mean'])  # Fwd Packet Length Mean
    feats.append(data['bwd_pkt_len_mean'])  # Bwd Packet Length Mean
    feats = np.array(feats).reshape(1, -1)
    feats = scaler.transform(feats)
    
    # Obtener predicción y probabilidad
    pred = model.predict(feats)[0]
    
    # Si se está usando un RandomForest, podemos obtener la confianza
    try:
        confianza = model.predict_proba(feats)[0][pred]
    except:
        confianza = 1.0  # Si no podemos obtener la probabilidad
    
    es_ataque = pred == 1
    resultado = "⚠️ ATAQUE" if es_ataque else "✅ BENIGNO"
    
    print(f"\n[{resultado}] {key} | {feats}")
    
    # Log solo si es un ataque
    if es_ataque:
        log_attack(key, data, confianza)

# 4. Captura en vivo
capture = pyshark.LiveCapture(interface=INTERFACE)
print("⏳ Capturando en tiempo real. Ctrl+C para detener.")
print(f"📝 Registrando ataques en: {LOG_FILE}")

try:
    for pkt in capture.sniff_continuously():
        key = get_flow_key(pkt)
        if not key:
            continue
        now = time.time()

        # Inicializa flujo
        if key not in flujos:
            flujos[key] = {
                'start': now,
                'last': now,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_pkt_lens': [],
                'bwd_pkt_lens': [],
            }

        flujo = flujos[key]
        flujo['last'] = now

        # Detección de dirección
        src, srcport, dst, dstport, proto = key
        try:
            if pkt.ip.src == src:
                # FWD (origen → destino)
                flujo['fwd_packets'] += 1
                flujo['fwd_bytes'] += int(pkt.length)
                flujo['fwd_pkt_lens'].append(int(pkt.length))
            else:
                # BWD (destino → origen)
                flujo['bwd_packets'] += 1
                flujo['bwd_bytes'] += int(pkt.length)
                flujo['bwd_pkt_lens'].append(int(pkt.length))
        except Exception:
            continue

        # Cierra y procesa el flujo por timeout
        finished_flows = []
        for fkey, fdata in flujos.items():
            if now - fdata['last'] > FLOW_TIMEOUT:
                # Calcula features necesarias
                duration = fdata['last'] - fdata['start']
                total_pkts = fdata['fwd_packets'] + fdata['bwd_packets']
                total_bytes = fdata['fwd_bytes'] + fdata['bwd_bytes']
                pkts_per_sec = total_pkts / duration if duration > 0 else 0
                bytes_per_sec = total_bytes / duration if duration > 0 else 0
                fwd_pkt_len_mean = np.mean(fdata['fwd_pkt_lens']) if fdata['fwd_pkt_lens'] else 0
                bwd_pkt_len_mean = np.mean(fdata['bwd_pkt_lens']) if fdata['bwd_pkt_lens'] else 0

                feat_dict = {
                    'duration': duration,
                    'fwd_packets': fdata['fwd_packets'],
                    'bwd_packets': fdata['bwd_packets'],
                    'fwd_bytes': fdata['fwd_bytes'],
                    'bwd_bytes': fdata['bwd_bytes'],
                    'bytes_per_sec': bytes_per_sec,
                    'pkts_per_sec': pkts_per_sec,
                    'fwd_pkt_len_mean': fwd_pkt_len_mean,
                    'bwd_pkt_len_mean': bwd_pkt_len_mean
                }
                process_flow(fkey, feat_dict)
                finished_flows.append(fkey)
        # Elimina flujos ya procesados
        for fkey in finished_flows:
            del flujos[fkey]

except KeyboardInterrupt:
    print("\nDetenido por usuario.")

print("🚦 Fin de la captura.")
