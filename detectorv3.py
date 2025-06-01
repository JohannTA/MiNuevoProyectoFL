import pyshark
import time
import torch
import joblib
import pandas as pd
import numpy as np
import socket
import psutil

# ===============================
# 1. Cargar modelo y preprocesadores
# ===============================
MODEL_DIR = 'model'  # Cambia si estás en tu PC

# Cargar modelo PyTorch
class SimpleMLP(torch.nn.Module):
    def __init__(self, input_dim, num_classes):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, num_classes)
        )
    def forward(self, x):
        return self.net(x)

# Cargar preprocesadores y features
pre = joblib.load(f"{MODEL_DIR}/preprocesamiento.pkl")
features = pre['features']

input_dim = len(features)
num_classes = 2  # ataque / normal

model = SimpleMLP(input_dim, num_classes)
model.load_state_dict(torch.load(f"{MODEL_DIR}/mlp_cicids2017.pth", map_location=torch.device('cpu')))
model.eval()

# ===============================
# 2. Obtener IPs locales confiables
# ===============================
def get_local_ips():
    local_ips = []
    for iface_name, iface_addresses in psutil.net_if_addrs().items():
        for address in iface_addresses:
            if address.family == socket.AF_INET:
                local_ips.append(address.address)
    if '127.0.0.1' not in local_ips:
        local_ips.append('127.0.0.1')
    return local_ips
TRUSTED_IPS = get_local_ips()

# ===============================
# 3. Interfaz de red (selección)
# ===============================
print("Sistema de detección de intrusiones (PyTorch)")
print("===========================================")
interfaces = list(psutil.net_if_addrs().keys())
for idx, iface in enumerate(interfaces):
    print(f"{idx}: {iface}")
selected_idx = int(input("Selecciona el número de la interfaz que deseas usar: "))
interface = interfaces[selected_idx]
print(f"Escuchando en {interface}... Ctrl+C para salir.")
print("===========================================")

# ===============================
# 4. Preprocesamiento de flujo para el modelo
# ===============================
def preprocesar_flujo(flujo, features):
    # Adaptar nombres/campos a lo entrenado
    d = {}
    for f in features:
        if f in flujo:
            d[f] = flujo[f]
        else:
            # Lógica para features expertas
            if f == 'is_https':
                d[f] = int((str(flujo.get('proto', '')).lower() == 'tcp') and (
                    str(flujo.get('dst_port', '')) == '443' or str(flujo.get('src_port', '')) == '443'))
            elif f == 'is_dns':
                d[f] = int((str(flujo.get('proto', '')).lower() == 'udp') and (
                    str(flujo.get('dst_port', '')) == '53' or str(flujo.get('src_port', '')) == '53'))
            else:
                d[f] = 0
    # Armar dataframe
    df = pd.DataFrame([d])
    # Normalizar numericas si es necesario
    return torch.tensor(df.values, dtype=torch.float32)

# ===============================
# 5. Clasificación de flujo en vivo
# ===============================
def detectar_flujo(flujo):
    x = preprocesar_flujo(flujo, features)
    with torch.no_grad():
        logits = model(x)
        probs = torch.softmax(logits, dim=1)
        clase = torch.argmax(probs, dim=1).item()
        prob = probs[0, clase].item()
    label_str = '🚨 ATAQUE' if clase == 0 else '✅ NORMAL'
    return label_str, prob, clase

# ===============================
# 6. Captura y flujo (simple por IP/puerto)
# ===============================
flows = {}
TIMEOUT_FLOW = 10  # segundos de inactividad para cerrar el flujo

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
    src_ip, src_port, dst_ip, dst_port, proto = key
    
    # Calcular estadísticas de longitud de paquetes si no existen
    if 'pkt_lengths' not in flow:
        flow['pkt_lengths'] = []
    if 'pkt_lengths_bwd' not in flow:
        flow['pkt_lengths_bwd'] = []
    
    # Calcular estadísticas de paquetes forward
    if len(flow['pkt_lengths']) > 0:
        flow['pkt_len_max'] = max(flow['pkt_lengths'])
        flow['pkt_len_min'] = min(flow['pkt_lengths']) 
        flow['pkt_len_mean'] = sum(flow['pkt_lengths']) / len(flow['pkt_lengths'])
        if len(flow['pkt_lengths']) > 1:
            flow['pkt_len_std'] = np.std(flow['pkt_lengths'])
        else:
            flow['pkt_len_std'] = 0
    else:
        flow['pkt_len_max'] = 0
        flow['pkt_len_min'] = 0
        flow['pkt_len_mean'] = 0
        flow['pkt_len_std'] = 0
    
    # Calcular estadísticas de paquetes backward
    if len(flow['pkt_lengths_bwd']) > 0:
        flow['pkt_bwd_max'] = max(flow['pkt_lengths_bwd'])
        flow['pkt_bwd_min'] = min(flow['pkt_lengths_bwd']) 
        flow['pkt_bwd_mean'] = sum(flow['pkt_lengths_bwd']) / len(flow['pkt_lengths_bwd'])
        if len(flow['pkt_lengths_bwd']) > 1:
            flow['pkt_bwd_std'] = np.std(flow['pkt_lengths_bwd'])
        else:
            flow['pkt_bwd_std'] = 0
    else:
        flow['pkt_bwd_max'] = 0
        flow['pkt_bwd_min'] = 0
        flow['pkt_bwd_mean'] = 0
        flow['pkt_bwd_std'] = 0
    
    # Calcular tasas (bytes/s y paquetes/s)
    duration = max(0.001, flow['duration'])  # Evitar división por cero
    flow['bytes_sec'] = flow['bytes'] / duration
    flow['pkt_sec'] = flow['count'] / duration
    
    flujo_features = {
        'proto': proto.lower() if proto else 'desconocido',
        'src_port': int(src_port),
        'dst_port': int(dst_port),
        'Flow_Duration': flow.get('duration', 0),
        'Total_Fwd_Packets': flow.get('count', 0),
        'Total_Backward_Packets': flow.get('count_bwd', 0),
        'Total_Length_of_Fwd_Packets': flow.get('bytes', 0),
        'Total_Length_of_Bwd_Packets': flow.get('bytes_bwd', 0),
        'Fwd_Packet_Length_Max': flow.get('pkt_len_max', 0),
        'Fwd_Packet_Length_Min': flow.get('pkt_len_min', 0),
        'Fwd_Packet_Length_Mean': flow.get('pkt_len_mean', 0),
        'Fwd_Packet_Length_Std': flow.get('pkt_len_std', 0),
        'Bwd_Packet_Length_Max': flow.get('pkt_bwd_max', 0),
        'Bwd_Packet_Length_Min': flow.get('pkt_bwd_min', 0),
        'Bwd_Packet_Length_Mean': flow.get('pkt_bwd_mean', 0),
        'Bwd_Packet_Length_Std': flow.get('pkt_bwd_std', 0),
        'Flow_Bytes/s': flow.get('bytes_sec', 0),
        'Flow_Packets/s': flow.get('pkt_sec', 0),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
    }
    resultado, prob, clase = detectar_flujo(flujo_features)
    flow_info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})"
    print(f"[{resultado}] {flow_info} | Clase: {clase} | Prob: {prob:.2f} | Paquetes: {flow['count']} | Bytes: {flow['bytes']} | Duración: {flow['duration']:.2f}s")

# ===============================
# 7. Captura de paquetes en tiempo real
# ===============================
cap = pyshark.LiveCapture(interface=interface)
for pkt in cap.sniff_continuously():
    now = time.time()
    key = get_flow_key(pkt)
    if key is None:
        continue
    src_ip, src_port, dst_ip, dst_port, proto = key
    length = int(getattr(pkt, 'length', 0))

    # Inicializa o actualiza el flujo
    if key not in flows:
        # Identificar dirección del flujo (heurística simple)
        is_outgoing = src_ip in TRUSTED_IPS
        flows[key] = {
            'start': now,
            'end': now,
            'count': 1,
            'count_bwd': 0,
            'bytes': length,
            'bytes_bwd': 0,
            'duration': 0,
            'pkt_lengths': [length],  # Lista para paquetes forward
            'pkt_lengths_bwd': [],    # Lista para paquetes backward
            'is_outgoing': is_outgoing
        }
    else:
        flows[key]['end'] = now
        flows[key]['count'] += 1
        flows[key]['bytes'] += length
        flows[key]['duration'] = flows[key]['end'] - flows[key]['start']
        flows[key]['pkt_lengths'].append(length)

    # Cierra flujos inactivos
    expired = []
    for k, f in flows.items():
        if now - f['end'] > TIMEOUT_FLOW:
            process_flow(k, f)
            expired.append(k)
    for k in expired:
        del flows[k]
