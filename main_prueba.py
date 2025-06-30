import joblib
import numpy as np

# Cargar el modelo y ver qué características espera
modelo_data = joblib.load('model/modelo_rf.pkl')

print("🔍 INFORMACIÓN DEL MODELO ENTRENADO:")
print("=" * 50)

# Verificar estructura del modelo
if isinstance(modelo_data, dict):
    print("✅ Estructura del modelo:")
    for key in modelo_data.keys():
        print(f"  - {key}")
    
    # Scaler info
    if 'scaler' in modelo_data:
        scaler = modelo_data['scaler']
        print(f"\n📊 Scaler espera: {scaler.n_features_in_} características")
        
        if hasattr(scaler, 'feature_names_in_'):
            print("📝 Características esperadas:")
            for i, feature in enumerate(scaler.feature_names_in_):
                print(f"  {i+1:2d}. {feature}")
        else:
            print("⚠️ No hay nombres de características guardados")
    
    # Features info
    if 'features' in modelo_data:
        features = modelo_data['features']
        print(f"\n📋 Features guardadas en modelo: {len(features)}")
        for i, feature in enumerate(features):
            print(f"  {i+1:2d}. {feature}")
    
    # Model info
    if 'model' in modelo_data:
        model = modelo_data['model']
        print(f"\n🤖 Modelo espera: {model.n_features_in_} características")
        if hasattr(model, 'feature_names_in_'):
            print("🏷️ Features del modelo:")
            for i, feature in enumerate(model.feature_names_in_):
                print(f"  {i+1:2d}. {feature}")

print("\n" + "=" * 50)