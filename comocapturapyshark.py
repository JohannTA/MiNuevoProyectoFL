import pyshark
import pandas as pd

columnas = [
    'ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service', 'duration',
    'src_bytes', 'dst_bytes', 'conn_state', 'missed_bytes', 'src_pkts', 'src_ip_bytes',
    'dst_pkts', 'dst_ip_bytes', 'dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode',
    'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected', 'http_trans_depth',
    'http_request_body_len', 'http_response_body_len', 'http_status_code'
]

def extraer_features(pkt):
    f = {}
    try:
        # Timestamp
        f['ts'] = float(getattr(pkt, 'sniff_timestamp', 0))
        # IP
        ip_layer = getattr(pkt, 'ip', None)
        f['src_ip'] = getattr(ip_layer, 'src', '0.0.0.0') if ip_layer else '0.0.0.0'
        f['dst_ip'] = getattr(ip_layer, 'dst', '0.0.0.0') if ip_layer else '0.0.0.0'
        # Transporte
        transport = getattr(pkt, 'transport_layer', None)
        if transport:
            trans_layer = getattr(pkt, transport.lower(), None)
            f['src_port'] = int(getattr(trans_layer, 'srcport', 0)) if trans_layer else 0
            f['dst_port'] = int(getattr(trans_layer, 'dstport', 0)) if trans_layer else 0
            f['proto'] = transport.lower()
        else:
            f['src_port'] = 0
            f['dst_port'] = 0
            f['proto'] = 'desconocido'
        # Defaults para el resto
        f['service'] = 'desconocido'
        f['duration'] = 0
        f['src_bytes'] = int(getattr(pkt, 'length', 0))
        f['dst_bytes'] = 0
        f['conn_state'] = 'desconocido'
        f['missed_bytes'] = 0
        f['src_pkts'] = 1
        f['src_ip_bytes'] = int(getattr(pkt, 'length', 0))
        f['dst_pkts'] = 0
        f['dst_ip_bytes'] = 0
        f['dns_query'] = 'desconocido'
        f['dns_qclass'] = 0
        f['dns_qtype'] = 0
        f['dns_rcode'] = 0
        f['dns_AA'] = 'desconocido'
        f['dns_RD'] = 'desconocido'
        f['dns_RA'] = 'desconocido'
        f['dns_rejected'] = 'desconocido'
        f['http_trans_depth'] = 0
        f['http_request_body_len'] = 0
        f['http_response_body_len'] = 0
        f['http_status_code'] = 0
    except Exception as e:
        print("Error robusto:", e)
        return None
    return f


# Captura por tiempo o por número de paquetes
cap = pyshark.LiveCapture(interface='Ethernet')  # Cambia por tu interfaz

dataset = []
print("Capturando paquetes, presiona Ctrl+C para terminar.")
for i, pkt in enumerate(cap.sniff_continuously()):
    try:
        features = extraer_features(pkt)
        dataset.append(features)
        if i >= 999:
            break
    except Exception as e:
        print("Error con paquete:", e)

# Convierte a DataFrame y guarda igual que tu CSV original
df = pd.DataFrame(dataset, columns=columnas)
df.to_csv("captura_dataset.csv", index=False)
print("Dataset guardado como captura_dataset.csv")
