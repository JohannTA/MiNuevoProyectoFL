import pyshark
import psutil
import joblib
import pandas as pd
import numpy as np

# Carga modelo, scaler y encoders
modelo_path = 'model/modelo_inicial.pkl'
scaler_path = 'model/scaler.pkl'
encoders_path = 'model/labelencoders.pkl'

modelo = joblib.load(modelo_path)
scaler = joblib.load(scaler_path)
encoders = joblib.load(encoders_path)

# Selección de interfaz amigable
net_if_addrs = psutil.net_if_addrs()
print("Interfaces de red disponibles (alias legible):")
interfaces = list(net_if_addrs.keys())
for idx, iface in enumerate(interfaces):
    print(f"{idx}: {iface}")
selected_idx = int(input("Selecciona el número de la interfaz que deseas usar: "))
interface = interfaces[selected_idx]
print(f"Usando interfaz: {interface}")

# El resto de tu pipeline:
columnas_modelo = [
    'ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service', 'duration',
    'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes', 'src_pkts', 'src_ip_bytes',
    'dst_pkts', 'dst_ip_bytes', 'dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode',
    'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected', 'http_trans_depth',
    'http_request_body_len', 'http_response_body_len', 'http_status_code'
]
cat_cols = ['proto', 'service', 'conn_state', 'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected']
num_cols = [col for col in columnas_modelo if col not in cat_cols and col not in ['src_ip', 'dst_ip', 'dns_query']]

def extraer_features(pkt):
    features = {}
    try:
        features['ts'] = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else 0
        features['src_ip'] = pkt.ip.src if hasattr(pkt, 'ip') else '0.0.0.0'
        features['dst_ip'] = pkt.ip.dst if hasattr(pkt, 'ip') else '0.0.0.0'
        features['src_port'] = int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, pkt.transport_layer) else 0
        features['dst_port'] = int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, pkt.transport_layer) else 0
        features['proto'] = pkt.transport_layer.lower() if hasattr(pkt, 'transport_layer') else 'desconocido'
        features['service'] = 'desconocido'
        features['duration'] = 0
        features['src_bytes'] = int(pkt.length) if hasattr(pkt, 'length') else 0
        features['dst_bytes'] = 0
        features['conn_state'] = 'desconocido'
        features['missed_bytes'] = 0
        features['src_pkts'] = 1
        features['src_ip_bytes'] = int(pkt.length) if hasattr(pkt, 'length') else 0
        features['dst_pkts'] = 0
        features['dst_ip_bytes'] = 0
        features['dns_query'] = 'desconocido'
        features['dns_qclass'] = 0
        features['dns_qtype'] = 0
        features['dns_rcode'] = 0
        features['dns_AA'] = 'desconocido'
        features['dns_RD'] = 'desconocido'
        features['dns_RA'] = 'desconocido'
        features['dns_rejected'] = 'desconocido'
        features['http_trans_depth'] = 0
        features['http_request_body_len'] = 0
        features['http_response_body_len'] = 0
        features['http_status_code'] = 0
    except Exception as e:
        print(f"Error extrayendo features: {e}")
        return None
    return features

cap = pyshark.LiveCapture(interface=interface)

print("🔴 Escuchando tráfico en tiempo real... Ctrl+C para detener.")

for pkt in cap.sniff_continuously():
    datos = extraer_features(pkt)
    if datos is None:
        continue

    df_nuevo = pd.DataFrame([datos], columns=columnas_modelo)
    for col in cat_cols:
        if col in df_nuevo and col in encoders:
            try:
                df_nuevo[col] = encoders[col].transform(df_nuevo[col].astype(str))
            except Exception:
                df_nuevo[col] = 0
    df_nuevo[num_cols] = scaler.transform(df_nuevo[num_cols])
    pred = modelo.predict(df_nuevo)[0]
    proba = modelo.predict_proba(df_nuevo)[0,1]
    etiqueta = "ATAQUE" if pred == 1 else "NORMAL"
    print(f"[{etiqueta}] Probabilidad de ataque: {proba:.2f} | src: {datos['src_ip']} -> dst: {datos['dst_ip']}")
