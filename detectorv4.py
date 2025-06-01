import pyshark
import time
import joblib
import numpy as np
import socket

# 1. Carga modelo y preprocesador
MODEL_DIR = 'model'  # Ajusta según donde tengas los .pkl
model = joblib.load(f'{MODEL_DIR}/modelo_rf.pkl')
pre = joblib.load(f'{MODEL_DIR}/preprocesamiento.pkl')
features = pre['features']
scaler = pre['scaler']

# 2. Parámetros de flujo
FLOW_TIMEOUT = 30  # Segundos de inactividad para cerrar un flujo
INTERFACE = 'Wi-Fi'  # Cambia por tu interfaz, ej: 'Wi-Fi' en Windows

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
    pred = model.predict(feats)[0]
    print(f"\n[{'⚠️ ATAQUE' if pred==1 else '✅ BENIGNO'}] {key} | {feats}")

# 4. Captura en vivo
capture = pyshark.LiveCapture(interface=INTERFACE)
print("⏳ Capturando en tiempo real. Ctrl+C para detener.")

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
