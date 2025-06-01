import torch
import joblib
import pandas as pd

# ==========================
# 1. Cargar modelo y preprocesamiento
# ==========================
MODEL_DIR = 'model'  # Ajusta si es necesario

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

# Cargar preprocesamiento
pre = joblib.load(f"{MODEL_DIR}/preprocesamiento.pkl")
features = pre['features']
scaler = pre['scaler']
cat_cols = pre['cat_cols']
num_cols = pre['num_cols']
encoders = pre['encoders']

input_dim = len(features)
num_classes = 2  # Binario

model = SimpleMLP(input_dim, num_classes)
model.load_state_dict(torch.load(f"{MODEL_DIR}/mlp_cicids2017.pth", map_location=torch.device('cpu')))
model.eval()

def preprocesar_flujo_manual(flujo):
    # Completa faltantes
    for f in features:
        if f not in flujo:
            flujo[f] = 0
    df = pd.DataFrame([flujo])

    # Codifica categóricas igual que en entrenamiento
    for col in cat_cols:
        le = encoders[col]
        if col in df:
            df[col] = df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else 0)
    # Escala numéricas
    df[num_cols] = scaler.transform(df[num_cols])
    return torch.tensor(df[features].values, dtype=torch.float32)

def detectar_flujo_manual(flujo):
    x = preprocesar_flujo_manual(flujo)
    with torch.no_grad():
        logits = model(x)
        probs = torch.softmax(logits, dim=1)
        clase = torch.argmax(probs, dim=1).item()
        prob = probs[0, clase].item()
    label_str = '🚨 ATAQUE' if clase == 0 else '✅ NORMAL'
    return label_str, prob, clase

# ==========================
# 2. Ejemplos de pruebas
# ==========================

# Ejemplo de tráfico normal (ajusta valores según tu dataset)
flujo_normal = {
    'proto': 'tcp',
    'src_port': 50000,
    'dst_port': 443,
    'Flow_Duration': 2,
    'Total_Fwd_Packets': 12,
    'Total_Backward_Packets': 8,
    'Total_Length_of_Fwd_Packets': 1500,
    'Total_Length_of_Bwd_Packets': 1500,
    'Fwd_Packet_Length_Max': 1500,
    'Fwd_Packet_Length_Min': 60,
    'Fwd_Packet_Length_Mean': 200,
    'Fwd_Packet_Length_Std': 80,
    'Bwd_Packet_Length_Max': 1500,
    'Bwd_Packet_Length_Min': 60,
    'Bwd_Packet_Length_Mean': 200,
    'Bwd_Packet_Length_Std': 80,
    'Flow_Bytes/s': 1200,
    'Flow_Packets/s': 10,
    'is_https': 1,
    'is_dns': 0
}

# Ejemplo de ataque (ajusta los valores para simular anormalidades)
flujo_ataque = {
    'proto': 'tcp',
    'src_port': 12345,
    'dst_port': 80,
    'Flow_Duration': 1,
    'Total_Fwd_Packets': 800,
    'Total_Backward_Packets': 2,
    'Total_Length_of_Fwd_Packets': 120000,
    'Total_Length_of_Bwd_Packets': 1000,
    'Fwd_Packet_Length_Max': 1500,
    'Fwd_Packet_Length_Min': 60,
    'Fwd_Packet_Length_Mean': 1000,
    'Fwd_Packet_Length_Std': 500,
    'Bwd_Packet_Length_Max': 300,
    'Bwd_Packet_Length_Min': 40,
    'Bwd_Packet_Length_Mean': 100,
    'Bwd_Packet_Length_Std': 60,
    'Flow_Bytes/s': 120000,
    'Flow_Packets/s': 1000,
    'is_https': 0,
    'is_dns': 0
}

# Otro ataque (DNS flood)
flujo_dns_flood = {
    'proto': 'udp',
    'src_port': 5678,
    'dst_port': 53,
    'Flow_Duration': 0.1,
    'Total_Fwd_Packets': 100,
    'Total_Backward_Packets': 0,
    'Total_Length_of_Fwd_Packets': 8000,
    'Total_Length_of_Bwd_Packets': 0,
    'Fwd_Packet_Length_Max': 100,
    'Fwd_Packet_Length_Min': 80,
    'Fwd_Packet_Length_Mean': 90,
    'Fwd_Packet_Length_Std': 8,
    'Bwd_Packet_Length_Max': 0,
    'Bwd_Packet_Length_Min': 0,
    'Bwd_Packet_Length_Mean': 0,
    'Bwd_Packet_Length_Std': 0,
    'Flow_Bytes/s': 80000,
    'Flow_Packets/s': 1000,
    'is_https': 0,
    'is_dns': 1
}

# Lista de pruebas
pruebas = [
    ("Tráfico normal", flujo_normal),
    ("Ataque HTTP", flujo_ataque),
    ("Ataque DNS flood", flujo_dns_flood),
]

for desc, flujo in pruebas:
    resultado, prob, clase = detectar_flujo_manual(flujo)
    print(f"{desc}: {resultado} | Prob: {prob:.2f} | Clase: {clase}")

