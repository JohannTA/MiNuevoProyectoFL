import pyshark
import time
import joblib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import socket
import datetime
import os
import psutil
from collections import defaultdict

# ====== Cargar modelo y preprocesadores ======
MODEL_PATH = 'model/mlp_flows.pth'
PREPROC_PATH = 'model/preprocesamiento.pkl'

preproc = joblib.load(PREPROC_PATH)
scaler = preproc['scaler']
encoders = preproc['encoders']
features = preproc['features']
num_cols = preproc['num_cols']
cat_cols = preproc['cat_cols']
le_label = preproc['le_label']

class SimpleMLP(nn.Module):
    def __init__(self, input_dim, num_classes):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes)
        )
    def forward(self, x):
        return self.net(x)

input_dim = len(features)
num_classes = len(le_label.classes_)
model = SimpleMLP(input_dim, num_classes)
model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device('cpu')))
model.eval()

# ====== Utilidades ======
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

def preprocesar_flujo_pytorch(flujo):
    fila = {}
    for col in features:
        val = flujo.get(col, 'desconocido' if col in cat_cols else 0)
        fila[col] = val
    df_flujo = pd.DataFrame([fila])
    for col in cat_cols:
        enc = encoders[col]
        val = str(df_flujo.at[0, col])
        # Si valor no está en encoder, forzar a 0
        if val in enc.classes_:
            df_flujo.at[0, col] = int(enc.transform([val])[0])
        else:
            df_flujo.at[0, col] = 0
        # Fuerza tipo int para esta columna
        df_flujo[col] = df_flujo[col].astype(int)
    df_flujo[num_cols] = scaler.transform(df_flujo[num_cols])
    x = torch.tensor(df_flujo[features].values, dtype=torch.float32)
    return x

def preprocesar_flujo_pytorch(flujo):
    fila = {}
    for col in features:
        val = flujo.get(col, 'desconocido' if col in cat_cols else 0)
        fila[col] = val
    df_flujo = pd.DataFrame([fila])

    # Codificar categóricas y forzar tipo
    for col in cat_cols:
        enc = encoders[col]
        val = str(df_flujo.at[0, col])
        if val in enc.classes_:
            df_flujo.at[0, col] = int(enc.transform([val])[0])
        else:
            df_flujo.at[0, col] = 0
        df_flujo[col] = df_flujo[col].astype(int)

    # Escalar numéricas
    df_flujo[num_cols] = scaler.transform(df_flujo[num_cols])

    # Forzar a tipo float TODO el DataFrame
    df_flujo = df_flujo.astype(float)

    # Convertir a tensor
    x = torch.tensor(df_flujo[features].values, dtype=torch.float32)
    return x

def predecir_flujo_pytorch(flujo):
    x = preprocesar_flujo_pytorch(flujo)
    with torch.no_grad():
        out = model(x)
        prob = torch.softmax(out, dim=1).cpu().numpy()[0]
        pred = np.argmax(prob)
        nombre_clase = le_label.inverse_transform([pred])[0]
        return pred, prob[pred], nombre_clase


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

def construir_flujo_para_modelo(key, flow):
    src_ip, src_port, dst_ip, dst_port, proto = key
    flujo = {
        'proto': proto if proto else 'desconocido',
        'service': flow.get('service', 'desconocido'),
        'duration': flow.get('duration', 0),
        'src_bytes': flow.get('src_bytes', 0),
        'dst_bytes': flow.get('dst_bytes', 0),
        'conn_state': flow.get('conn_state', 'desconocido'),
        'missed_bytes': flow.get('missed_bytes', 0),
        'src_pkts': flow.get('src_pkts', flow.get('count', 0)),
        'src_ip_bytes': flow.get('src_ip_bytes', flow.get('src_bytes', 0)),
        'dst_pkts': flow.get('dst_pkts', 0),
        'dst_ip_bytes': flow.get('dst_ip_bytes', flow.get('dst_bytes', 0)),
        'dns_qclass': flow.get('dns_qclass', 0),
        'dns_qtype': flow.get('dns_qtype', 0),
        'dns_rcode': flow.get('dns_rcode', 0),
        'dns_AA': flow.get('dns_AA', 'desconocido'),
        'dns_RD': flow.get('dns_RD', 'desconocido'),
        'dns_RA': flow.get('dns_RA', 'desconocido'),
        'dns_rejected': flow.get('dns_rejected', 'desconocido'),
        'http_trans_depth': flow.get('http_trans_depth', 0),
        'http_request_body_len': flow.get('http_request_body_len', 0),
        'http_response_body_len': flow.get('http_response_body_len', 0),
        'http_status_code': flow.get('http_status_code', 0),
        # NO incluyas label, type ni ts
    }
    return flujo

def main():
    print("Sistema de detección de intrusiones basado en flujos (PyTorch MLP)")
    print("========================================================")
    print("Interfaces de red (elige tu alias/índice):")
    net_if_addrs = psutil.net_if_addrs()
    interfaces = list(net_if_addrs.keys())
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    selected_idx = int(input("Selecciona el número de la interfaz que deseas usar: "))
    interface = interfaces[selected_idx]
    print(f"Escuchando en {interface}... Ctrl+C para salir.")
    print("========================================================")

    TIMEOUT_FLOW = 10
    flows = {}
    cap = pyshark.LiveCapture(interface=interface)
    for pkt in cap.sniff_continuously():
        now = time.time()
        key = get_flow_key(pkt)
        if key is None:
            continue

        src_ip, src_port, dst_ip, dst_port, proto = key
        length = int(getattr(pkt, 'length', 0))
        conn_state = 'UNK'
        if proto == 'TCP' and hasattr(pkt.tcp, 'flags'):
            flags = pkt.tcp.flags
            if '0x0002' in flags:
                conn_state = 'SYN'
            elif '0x0014' in flags:
                conn_state = 'REJ'
            elif '0x0010' in flags:
                conn_state = 'EST'

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
                'missed_bytes': 0,
                'src_pkts': 1,
                'src_ip_bytes': length,
                'dst_pkts': 0,
                'dst_ip_bytes': 0,
                'dns_qclass': 0,
                'dns_qtype': 0,
                'dns_rcode': 0,
                'dns_AA': 'desconocido',
                'dns_RD': 'desconocido',
                'dns_RA': 'desconocido',
                'dns_rejected': 'desconocido',
                'http_trans_depth': 0,
                'http_request_body_len': 0,
                'http_response_body_len': 0,
                'http_status_code': 0,
                'service': dst_port,
            }
        else:
            flows[key]['end'] = now
            flows[key]['count'] += 1
            flows[key]['bytes'] += length
            flows[key]['src_bytes'] += length
            flows[key]['duration'] = flows[key]['end'] - flows[key]['start']
            flows[key]['src_pkts'] += 1
            flows[key]['src_ip_bytes'] += length
            # Si tienes cómo detectar dst_pkts y dst_ip_bytes, agrégalo aquí.

        # Cerrar flujos inactivos
        expired = []
        for k, f in flows.items():
            if now - f['end'] > TIMEOUT_FLOW:
                flujo_features = construir_flujo_para_modelo(k, f)
                pred, prob, clase = predecir_flujo_pytorch(flujo_features)
                src_ip, src_port, dst_ip, dst_port, proto = k
                flow_info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})"
                if pred == 1:  # Ajusta según tu encoding
                    print(f"[🚨 ATAQUE] {flow_info} | Clase: {clase} | Prob: {prob:.2f} | Paquetes: {f['count']} | Bytes: {f['bytes']} | Duración: {f['duration']:.2f}s")
                else:
                    print(f"[✅ NORMAL] {flow_info} | Clase: {clase} | Prob: {prob:.2f} | Paquetes: {f['count']} | Bytes: {f['bytes']} | Duración: {f['duration']:.2f}s")
                expired.append(k)
        for k in expired:
            del flows[k]

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDetector detenido por el usuario.")
    except Exception as e:
        print(f"Error: {e}")
