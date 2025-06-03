import joblib
import numpy as np
import pandas as pd
import pyshark

# 1. Cargar modelo y preprocesador
modelo_path = 'model/modelo_rf.pkl'
prepro_path = 'model/preprocesamiento.pkl'
clf = joblib.load(modelo_path)
prepro = joblib.load(prepro_path)
scaler = prepro['scaler']
feature_names = prepro['features']

# 2. Función para extraer features de un flujo de paquetes (ajusta según tus necesidades)
def extract_features_from_flow(packets):
    # Debes ajustar para que coincida EXACTAMENTE con la lógica del dataset CICIDS2017.
    # Aquí va un ejemplo básico:
    flow_duration = (packets[-1].sniff_time - packets[0].sniff_time).total_seconds() * 1e6  # en microsegundos (igual que CICIDS2017)
    total_fwd_packets = sum(1 for p in packets if p.ip.src < p.ip.dst)
    total_backward_packets = sum(1 for p in packets if p.ip.src > p.ip.dst)
    total_length_of_fwd_packets = sum(int(p.length) for p in packets if p.ip.src < p.ip.dst)
    total_length_of_bwd_packets = sum(int(p.length) for p in packets if p.ip.src > p.ip.dst)
    # ... demás features, recuerda replicar la lógica del dataset.
    # Si algún feature no puedes calcularlo en tiempo real, pon np.nan o 0 pero documenta por qué.
    # Ejemplo ficticio:
    features = {
        'flow_duration': flow_duration,
        'total_fwd_packets': total_fwd_packets,
        'total_backward_packets': total_backward_packets,
        'total_length_of_fwd_packets': total_length_of_fwd_packets,
        'total_length_of_bwd_packets': total_length_of_bwd_packets,
        # ...
    }
    # Suplimos los faltantes con 0 o np.nan según corresponda
    for key in feature_names:
        if key not in features:
            features[key] = 0
    return [features[f] for f in feature_names]

# 3. Captura de tráfico en vivo y predicción
def detectar_en_tiempo_real(interface='eth0', ventana_seg=10):
    capture = pyshark.LiveCapture(interface=interface)
    packets = []
    inicio = None
    for packet in capture.sniff_continuously():
        try:
            # Puedes filtrar por IP, TCP/UDP, puerto, etc. si lo requieres
            if not hasattr(packet, 'ip'):
                continue
            if inicio is None:
                inicio = packet.sniff_time
            packets.append(packet)
            # Cierra ventana cuando pase la cantidad de segundos deseada
            if (packet.sniff_time - inicio).total_seconds() >= ventana_seg:
                # Extrae features
                features = extract_features_from_flow(packets)
                features_df = pd.DataFrame([features], columns=feature_names)
                # Preprocesa igual que en entrenamiento
                features_scaled = scaler.transform(features_df)
                pred = clf.predict(features_scaled)[0]
                proba = clf.predict_proba(features_scaled)[0]
                print(f"Predicción: {'ATAQUE' if pred==1 else 'BENIGNO'} (Probabilidad ataque: {proba[1]:.2f})")
                # Reinicia para siguiente ventana
                packets = []
                inicio = None
        except Exception as e:
            print(f"Error procesando paquete: {e}")

if __name__ == '__main__':
    detectar_en_tiempo_real(interface='Wi-Fi', ventana_seg=10)