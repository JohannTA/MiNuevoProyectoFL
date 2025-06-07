
#!/bin/bash

# Configuración
SERVER_IP="192.168.1.100"  # CAMBIAR POR TU IP REAL
SERVER_PORT="8765"
CLIENT_NAME="IDS-$(hostname)"
LOCATION="Ubuntu VM - $(hostname -I | awk '{print $1}')"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

echo "🚀 Iniciando Cliente Federado IDS"
echo "🖥️  Servidor: $SERVER_IP:$SERVER_PORT"
echo "🏷️  Cliente: $CLIENT_NAME"
echo "📍 Ubicación: $LOCATION"
echo "🔌 Interfaz: $INTERFACE"
echo ""

# Verificar conectividad
echo "🔍 Verificando servidor..."
if ping -c 1 $SERVER_IP >/dev/null 2>&1; then
    echo "✅ Servidor alcanzable"
else
    echo "❌ No se puede alcanzar $SERVER_IP"
    echo "💡 Verifica que el servidor esté ejecutándose"
    exit 1
fi

# Activar entorno virtual si existe
if [ -d "venv" ]; then
    echo "🔧 Activando entorno virtual..."
    source venv/bin/activate
fi

# Verificar dependencias
echo "📦 Verificando dependencias..."
python3 -c "import websockets, numpy, sklearn, joblib; print('✅ Dependencias OK')" || {
    echo "❌ Faltan dependencias. Instala con: pip install -r req_client.txt"
    exit 1
}

echo "🔄 Iniciando cliente federado..."

# Iniciar cliente
python3 cliente_federado.py \
  --server "ws://$SERVER_IP:$SERVER_PORT" \
  --name "$CLIENT_NAME" \
  --location "$LOCATION" \
  --interface "$INTERFACE"

echo "👋 Cliente federado finalizado"
EOF

# Hacer ejecutable
chmod +x start_federated_client.sh