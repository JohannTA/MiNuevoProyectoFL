#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
import subprocess
import threading
import time
import datetime
import signal
import json
import sqlite3
import os
from pathlib import Path
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DetectorFederado:
    """Detector integrado que se conecta al servidor federado"""
    
        # BUSCAR el constructor __init__ (línea ~25) Y CORREGIR línea 63:
    
    def __init__(self, user_id, interface, model_path, flask_url="http://localhost:5000",servidor_federado_url=None):
        # Parámetros básicos
        self.user_id = user_id
        self.interface = interface
        self.model_path = model_path
        self.flask_api_url = flask_url.rstrip('/')
        self.servidor_federado_url = servidor_federado_url  # Para WebSocket federado
        # Configuración del servidor federado (desde main.py)  # Se obtiene desde main.py
        
        # Información del usuario
        self.user_info = None
        self.computing_device_info = None
        self.client_id = None
        
        # Estado del detector
        self.detector_process = None
        self.running = False
        self.start_time = None
        # Cliente WebSocket federado
        self.federado_client = None
        self.websocket = None

        # Estadísticas
        self.stats = {
            'lines_processed': 0,
            'total_packets': 0,
            'normal_packets': 0,
            'anomalies_detected': 0,
            'attacks_detected': 0,
            'detections_sent': 0,
            'last_detection': None
        }
        
        # Base de datos local para respaldo
        self.local_backup_db = f"detector_backup_user_{user_id}.db"
        self.inicializar_respaldo_local()
        
        # Configurar señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        #    CAMBIAR ESTAS LÍNEAS (líneas 63-64):
        print(f"[CONFIG] Detector configurado para usuario {user_id}")
        print(f"[CONFIG] Conectara con: {self.flask_api_url}")

    def inicializar_respaldo_local(self):
        """Inicializa la base de datos local de respaldo"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detecciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id TEXT,
                timestamp TEXT,
                anomaly_type TEXT,
                severity TEXT,
                confidence_score REAL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                enviado_servidor BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            conn.commit()
            conn.close()
            #    CAMBIAR ESTA LÍNEA:
            print(f"[DB] Base de datos local inicializada: {self.local_backup_db}")
            
        except Exception as e:
            #    CAMBIAR ESTA LÍNEA:
            print(f"[WARNING] Error inicializando respaldo local: {e}")
    def obtener_info_usuario(self):
        """Obtiene información del usuario desde el servidor Flask"""
        try:
            url = f"{self.flask_api_url}/api/users/{self.user_id}/complete-info"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"  Error obteniendo info usuario: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            print(f"  Error conectando con servidor: {e}")
            return None

    def obtener_config_servidor_federado(self):
        """Obtiene la configuración del servidor federado desde main.py"""
        try:
            url = f"{self.flask_api_url}/api/federado/status"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('running'):
                    # El servidor federado está corriendo
                    self.servidor_federado_url = result.get('server_url', 'ws://localhost:8765')
                    return True
                else:
                    print("  Servidor federado no está corriendo")
                    return False
            else:
                print("  No se pudo obtener estado del servidor federado")
                return False
                
        except Exception as e:
            print(f"  Error verificando servidor federado: {e}")
            return False
    
    async def conectar_servidor_federado(self):
        """Conecta al servidor federado WebSocket"""
        if not self.servidor_federado_url:
            print("[WARNING] URL del servidor federado no configurada")
            return False
        
        try:
            import websockets
            self.websocket = await websockets.connect(self.servidor_federado_url)
            
            # Registrar cliente
            registration = {
                'type': 'register',
                'name': f'Detector-User-{self.user_id}',
                'location': f'Device-{self.computing_device_info.get("model", "Unknown")}',
                'interface': self.interface,
                'capabilities': ['intrusion_detection', 'model_training'],
                'version': '1.0'
            }
            
            await self.websocket.send(json.dumps(registration))
            response = await self.websocket.recv()
            response_data = json.loads(response)
            
            if response_data['type'] == 'registration_confirmed':
                print(f"[OK] Conectado al servidor federado: {self.servidor_federado_url}")
                self.client_id = response_data.get('client_id')
                return True
            else:
                print(f"[ERROR] Error en registro federado: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Error conectando servidor federado: {e}")
            return False

    def iniciar_detector_proceso(self):
        """Proceso principal del detector federado"""
        try:
            print(" INICIANDO DETECTOR FEDERADO")
            print("=" * 60)
            
            # Paso 1: Obtener información del usuario
            print("   Paso 1: Obteniendo información del usuario...")
            user_data = self.obtener_info_usuario()
            if not user_data or not user_data.get('success'):
                print("No se pudo obtener información del usuario")
                return False
            
            self.user_info = user_data['user']
            self.computing_device_info = user_data.get('computing_device')
            print(f"   Usuario: {self.user_info['username']} ({self.user_info['first_name']} {self.user_info['last_name']})")
            
            if self.computing_device_info:
                print(f" Dispositivo: {self.computing_device_info['brand']} {self.computing_device_info['model']}")
            
            # Paso 2: Verificar modelo
            print("   Paso 2: Verificando modelo...")
            if not os.path.exists(self.model_path):
                print(f"Modelo no encontrado: {self.model_path}")
                return False
            print(f"   Modelo encontrado: {self.model_path}")
            
            # Paso 3: Verificar detector.py
            print("   Paso 3: Verificando detector.py...")
            if not os.path.exists('detector.py'):
                print("detector.py no encontrado")
                return False
            print("   detector.py encontrado")
            
            # Paso 4: Verificar conectividad con servidor federado
            print("   Paso 4: Verificando servidor federado...")
            federado_disponible = self.obtener_config_servidor_federado()
            if federado_disponible:
                print(f"   Servidor federado disponible: {self.servidor_federado_url}")
                # ✅ AGREGAR CONEXIÓN WEBSOCKET:
                try:
                    import asyncio
                    
                    # Conectar al servidor federado WebSocket  
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    federado_conectado = loop.run_until_complete(self.conectar_servidor_federado())
                    loop.close()
                    
                    if federado_conectado:
                        print("   [OK] Conectado al servidor federado via WebSocket")
                        self.federado_connected = True
                    else:
                        print("   [WARNING] No se pudo conectar al servidor federado")
                        
                except Exception as e:
                    print(f"   [WARNING] Error conectando WebSocket federado: {e}")
            else:
                print("  Servidor federado no disponible - funcionando en modo local")
            
            print("=" * 60)
            print(" INICIANDO DETECTOR DE TRÁFICO DE RED")
            print("=" * 60)
            
            # Iniciar tiempo
            self.start_time = datetime.datetime.now()
            self.running = True
            
            # Ejecutar detector
            return self.ejecutar_detector()
            
        except Exception as e:
            print(f" Error en inicialización: {e}")
            return False

    def ejecutar_detector(self):
        """Ejecuta el detector principal con salida a consola"""
        try:
            # Comando para ejecutar detector.py
            cmd = [
                'python', 'detector.py',
                '--interface', self.interface,
                '--model', self.model_path
            ]
            
            print(f" Ejecutando: {' '.join(cmd)}")
            print(" Iniciando captura de tráfico...")
            print(" Presiona Ctrl+C para detener")
            print("=" * 60)
            
            # Iniciar proceso del detector
            self.detector_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Procesar salida línea por línea
            line_count = 0
            for linea in iter(self.detector_process.stdout.readline, ''):
                if linea:
                    line_count += 1
                    linea_limpia = linea.rstrip()
                    
                    # ✅ MOSTRAR TODO - SIN FILTROS NI CATEGORÍAS:
                    print(linea_limpia)  # ← SALIDA EXACTA COMO VIENE DEL DETECTOR
                    
                    # Procesamiento en segundo plano (sin afectar la salida)
                    try:
                        # Parsear detecciones en silencio
                        deteccion = self.parsear_salida_detector(linea)
                        if deteccion:
                            self.guardar_respaldo_local(deteccion)
                            
                            # Enviar al servidor si supera umbral
                            if deteccion.get('confidence_score', 0) >= 0.3:
                                enviado = self.enviar_deteccion_servidor(deteccion)
                                if enviado:
                                    self.marcar_enviado_respaldo(deteccion.get('detection_id'))
                        
                        # Actualizar estadísticas en silencio
                        self.actualizar_estadisticas(linea)
                        
                    except Exception:
                        # Ignorar errores de procesamiento para no interrumpir la salida
                        pass
            
                # Verificar si el proceso sigue corriendo
                if self.detector_process.poll() is not None:
                    break
        
            # Proceso terminado
            return_code = self.detector_process.poll()
            print("=" * 60)
            print(f"[END] Detector terminado con código: {return_code}")
        
            
        except Exception as e:
            print(f"Error ejecutando detector: {e}")
            return False
        finally:
            self.detener()

    def parsear_salida_detector(self, linea):
        """Parsea la salida del detector para extraer detecciones"""
        try:
            # Buscar patrones de detección en la línea
            if any(keyword in linea.upper() for keyword in ['ATTACK', 'INTRUSION', 'ANOMALY']):
                # Crear detección básica (en una implementación real, harías parsing más sofisticado)
                deteccion = {
                    'detection_id': f"det_{int(time.time() * 1000)}",
                    'timestamp': datetime.datetime.now().isoformat(),
                    'anomaly_type': 'Network Anomaly',
                    'severity': 'medium',
                    'confidence_score': 0.75,
                    'source_ip': '192.168.1.100',
                    'destination_ip': '192.168.1.1',
                    'source_port': 12345,
                    'destination_port': 80,
                    'protocol': 'TCP',
                    'user_id': self.user_id,
                    'model_id': 1,
                    'client_id': self.client_id,
                    'raw_output': linea.strip()
                }
                
                return deteccion
            
            return None
            
        except Exception as e:
            print(f"  Error parseando línea: {e}")
            return None

    def guardar_respaldo_local(self, deteccion):
        """Guarda detección en base de datos local"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO detecciones 
            (detection_id, timestamp, anomaly_type, severity, confidence_score,
             source_ip, destination_ip, source_port, destination_port, protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                deteccion.get('detection_id'),
                deteccion.get('timestamp'),
                deteccion.get('anomaly_type'),
                deteccion.get('severity'),
                deteccion.get('confidence_score'),
                deteccion.get('source_ip'),
                deteccion.get('destination_ip'),
                deteccion.get('source_port'),
                deteccion.get('destination_port'),
                deteccion.get('protocol')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"  Error guardando respaldo: {e}")

    def enviar_deteccion_servidor(self, deteccion):
        """Envía detección al servidor Flask"""
        try:
            url = f"{self.flask_api_url}/api/buffer/add-detection"
            
            response = requests.post(
                url,
                json=deteccion,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.stats['detections_sent'] += 1
                    return True
            
            print(f"  Error enviando detección: HTTP {response.status_code}")
            return False
            
        except Exception as e:
            print(f"  Error enviando detección: {e}")
            return False
    
    def marcar_enviado_respaldo(self, detection_id):
        """Marca detección como enviada en respaldo local"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE detecciones SET enviado_servidor = 1 WHERE detection_id = ?",
                (detection_id,)
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"  Error marcando como enviado: {e}")

    def actualizar_estadisticas(self, linea):
        """Actualiza estadísticas locales"""
        self.stats['lines_processed'] += 1
        
        if 'NORMAL' in linea.upper():
            self.stats['normal_packets'] += 1
        elif any(keyword in linea.upper() for keyword in ['ANOMALY', 'ATTACK', 'INTRUSION']):
            self.stats['anomalies_detected'] += 1
            if 'ATTACK' in linea.upper():
                self.stats['attacks_detected'] += 1
        
        self.stats['total_packets'] = self.stats['normal_packets'] + self.stats['anomalies_detected']

    def signal_handler(self, signum, frame):
        """Maneja señales del sistema"""
        print(f"\n Señal {signum} recibida - Deteniendo detector...")
        self.detener()
        sys.exit(0)

    def detener(self):
        """Detiene el detector y muestra estadísticas finales"""
        try:
            self.running = False
            
            print("\n" + "=" * 60)
            print("RESUMEN FINAL DE LA SESIÓN")
            print("=" * 60)
            
            if self.start_time:
                runtime = datetime.datetime.now() - self.start_time
                print(f"Tiempo de ejecución: {runtime}")
            
            print(f"Líneas procesadas: {self.stats['lines_processed']:,}")
            print(f"Total de paquetes: {self.stats['total_packets']:,}")
            print(f"Paquetes normales: {self.stats['normal_packets']:,}")
            print(f" Anomalías detectadas: {self.stats['anomalies_detected']}")
            print(f" Ataques detectados: {self.stats['attacks_detected']}")
            print(f" Detecciones enviadas: {self.stats['detections_sent']}")
            print(f" Respaldo local: {self.local_backup_db}")
            
            print("=" * 60)
            print("   Sesión finalizada correctamente")
            
            # Terminar proceso si sigue corriendo
            if self.detector_process and self.detector_process.poll() is None:
                self.detector_process.terminate()
                print(" Proceso detector terminado")
                
        except Exception as e:
            print(f"Error en cleanup: {e}")


# BUSCAR la función main() (línea ~477) Y REEMPLAZAR:

def main():
    """Función principal del detector integrado"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Detector Integrado Federado',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python detector_integrado.py --user-id 1 --interface "Wi-Fi" --model "model/modelo_rf.pkl" --flask-url "http://localhost:5000"
  
Requisitos:
  - main.py ejecutándose en la URL especificada
  - PostgreSQL configurado con datos del usuario
  - detector.py en el directorio actual
  - Modelo ML disponible
        """
    )
    
    parser.add_argument('--user-id', type=int, required=True, 
                       help='ID del usuario en PostgreSQL')
    parser.add_argument('--interface', required=True, 
                       help='Interfaz de red a monitorear (ej: "Wi-Fi", "Ethernet")')
    parser.add_argument('--model', required=True, 
                       help='Ruta al modelo de Machine Learning')
    parser.add_argument('--flask-url', required=True,
                       help='URL del servidor Flask (ej: http://localhost:5000)')
    parser.add_argument('--servidor-federado', default='ws://192.168.18.88:8765',
                       help='URL del servidor federado WebSocket (ej: ws://192.168.18.88:8765)')
    args = parser.parse_args()
    
    #    REEMPLAZAR EMOJIS POR TEXTO SEGURO:
    print("=" * 50)
    print("DETECTOR INTEGRADO FEDERADO")  # ← SIN EMOJI
    print("=" * 50)
    print(f"User ID: {args.user_id}")
    print(f"Interfaz: {args.interface}")
    print(f"Modelo: {args.model}")
    print(f"Flask URL: {args.flask_url}")
    print("=" * 50)
    
    # Crear detector
    detector = DetectorFederado(
        user_id=args.user_id,
        interface=args.interface,
        model_path=args.model,
        flask_url=args.flask_url,  # ← AGREGAR COMA
        servidor_federado_url=args.servidor_federado
    )
    
    try:
        # Iniciar detector
        detector.iniciar_detector_proceso()
        
    except KeyboardInterrupt:
        print("Detenido por el usuario (Ctrl+C)")
        detector.detener()
    except Exception as e:
        print(f"Error fatal: {e}")
        detector.detener()
        sys.exit(1)


if __name__ == "__main__":
    main()