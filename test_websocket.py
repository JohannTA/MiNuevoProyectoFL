import asyncio
import websockets
import json
import time

async def test_server():
    uri = "ws://192.168.18.88:8765"
    print(f"🔍 Conectando a {uri}")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Conexión WebSocket exitosa")
            
            # Enviar registro de cliente
            registro = {
                "type": "register",
                "name": "Test-Client",
                "location": "Debug",
                "capabilities": ["test"],
                "version": "1.0"
            }
            
            await websocket.send(json.dumps(registro))
            print("📤 Registro enviado")
            
            # Esperar respuesta
            response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            print(f"📥 Respuesta: {response}")
            
            # Enviar detección de prueba
            deteccion = {
                "type": "detection_alert",
                "client_id": "test-123",
                "alert": {
                    "status": "suspicious",
                    "src_ip": "192.168.1.100",
                    "dst_ip": "192.168.1.1",
                    "score": 0.85,
                    "attack_type": "Test Alert"
                }
            }
            
            await websocket.send(json.dumps(deteccion))
            print("📤 Detección de prueba enviada")
            
            await asyncio.sleep(2)
            print("✅ Test completado exitosamente")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_server())