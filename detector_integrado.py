#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detector Integrado Completo - Versión Final
--------------------------------------------
Muestra TODA la salida de detector.py + integración completa con PostgreSQL
"""

import sys
import os
import json
import threading
import time
import subprocess
import requests
import re
import sqlite3
from datetime import datetime
import logging
import uuid
import signal

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DetectorFederado:
    """Detector federado que muestra toda la salida del detector.py"""
    
    def __init__(self, user_id, interface, model_path):
        # Parámetros básicos
        self.user_id = user_id
        self.interface = interface
        self.model_path = model_path
        
        # Configuración del servidor
        self.flask_api_url = "http://localhost:5000"
        self.local_backup_db = f"detector_backup_user_{user_id}.db"
        
        # Información del usuario (obtenida desde PostgreSQL)
        self.user_info = None
        self.computing_device_info = None
        self.client_id = None
        
        # Estado del detector
        self.detector_process = None
        self.running = False
        self.detections_sent = 0
        self.lines_processed = 0
        self.start_time = None
        
        # Estadísticas
        self.stats = {
            'total_packets': 0,
            'normal_packets': 0,
            'anomaly_packets': 0,
            'attacks_detected': 0,
            'last_detection': None
        }
        
        # Inicializar base de datos local
        self.inicializar_respaldo_local()
        
        # Configurar manejadores de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Manejador de señales para cierre limpio"""
        print(f"\n🛑 Señal recibida ({signum}). Cerrando detector...")
        self.detener()
        sys.exit(0)
    
    def inicializar_respaldo_local(self):
        """Inicializa la base de datos local de respaldo"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            # Tabla de detecciones de respaldo
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detections_backup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id TEXT UNIQUE,
                    user_id INTEGER,
                    client_id TEXT,
                    timestamp TEXT,
                    anomaly_type TEXT,
                    severity TEXT,
                    confidence_score REAL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    raw_data TEXT,
                    sent_to_server BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla de estadísticas de sesión
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS session_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_start TEXT,
                    session_end TEXT,
                    total_packets INTEGER DEFAULT 0,
                    detections_sent INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Base de datos local inicializada: {self.local_backup_db}")
            
        except Exception as e:
            logger.error(f"❌ Error inicializando respaldo local: {e}")
    
    def obtener_informacion_usuario(self):
        """Obtiene información completa del usuario desde PostgreSQL"""
        try:
            print(f"\n📋 Obteniendo información del usuario ID: {self.user_id}")
            print("🔗 Conectando con el servidor PostgreSQL...")
            
            response = requests.get(
                f"{self.flask_api_url}/api/users/{self.user_id}/complete-info",
                timeout=15,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success'):
                    self.user_info = data.get('user')
                    self.computing_device_info = data.get('computing_device')
                    
                    if self.user_info and self.computing_device_info:
                        self.client_id = str(self.computing_device_info.get('id'))
                        
                        print("\n" + "="*70)
                        print("📋 INFORMACIÓN DEL USUARIO OBTENIDA DESDE POSTGRESQL")
                        print("="*70)
                        print(f"🆔 ID Usuario: {self.user_info.get('id')}")
                        print(f"👤 Nombre: {self.user_info.get('first_name')} {self.user_info.get('last_name')}")
                        print(f"🏷️ Username: {self.user_info.get('username')}")
                        print(f"📧 Email: {self.user_info.get('email')}")
                        print(f"👔 Rol: {self.user_info.get('role_display_name')}")
                        print(f"🔲 Estado: {'Activo' if self.user_info.get('is_active') else 'Inactivo'}")
                        print("─" * 70)
                        print("💻 DISPOSITIVO DE CÓMPUTO ASIGNADO:")
                        print(f"🆔 Device ID: {self.computing_device_info.get('id')}")
                        print(f"🏷️ Tipo: {self.computing_device_info.get('type')}")
                        print(f"🖥️ Marca: {self.computing_device_info.get('brand')}")
                        print(f"📦 Modelo: {self.computing_device_info.get('model')}")
                        print(f"🔢 Serial: {self.computing_device_info.get('serial_number')}")
                        print(f"🔧 Estado: {self.computing_device_info.get('status')}")
                        print(f"🎯 Client ID: {self.client_id}")
                        print("="*70)
                        
                        return True
                    else:
                        print(f"❌ Usuario {self.user_id} no tiene dispositivo de cómputo asignado")
                        print("💡 Verifica la configuración en PostgreSQL")
                        return False
                else:
                    error_msg = data.get('error', 'Error desconocido')
                    print(f"❌ Error del servidor: {error_msg}")
                    return False
            else:
                print(f"❌ Error HTTP {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print("❌ No se puede conectar con el servidor Flask")
            print("💡 Asegúrate de que main_prueba.py esté ejecutándose en localhost:5000")
            print("💡 Comando: python main_prueba.py")
            return False
        except requests.exceptions.Timeout:
            print("❌ Timeout conectando con el servidor")
            return False
        except Exception as e:
            print(f"❌ Error obteniendo información del usuario: {e}")
            return False
    
    def generar_detection_id(self):
        """Genera un ID único para la detección"""
        timestamp = int(datetime.now().timestamp() * 1000)
        return f"user_{self.user_id}_dev_{self.client_id}_{timestamp}_{self.detections_sent}"
    
    def enviar_deteccion_servidor(self, deteccion_data):
        """Envía detección al servidor PostgreSQL"""
        detection_id = self.generar_detection_id()
        
        # Siempre guardar en respaldo local primero
        self.guardar_respaldo_local(detection_id, deteccion_data)
        
        # Intentar enviar al servidor
        try:
            url = f"{self.flask_api_url}/api/buffer/add-detection"
            
            # Preparar payload completo
            payload = {
                'detection_id': detection_id,
                'user_id': self.user_id,
                'client_id': int(self.client_id),
                'timestamp': datetime.now().isoformat(),
                'source_ip': deteccion_data.get('source_ip', '192.168.1.100'),
                'destination_ip': deteccion_data.get('destination_ip', '192.168.1.1'),
                'source_port': deteccion_data.get('source_port', 80),
                'destination_port': deteccion_data.get('destination_port', 443),
                'protocol': deteccion_data.get('protocol', 'TCP'),
                'anomaly_type': deteccion_data.get('anomaly_type', 'Network Anomaly'),
                'severity': deteccion_data.get('severity', 'medium'),
                'confidence_score': float(deteccion_data.get('confidence_score', 0.75)),
                'raw_data': {
                    'user_info': {
                        'user_id': self.user_id,
                        'username': self.user_info.get('username'),
                        'full_name': f"{self.user_info.get('first_name')} {self.user_info.get('last_name')}",
                        'role': self.user_info.get('role_display_name'),
                        'email': self.user_info.get('email'),
                        'is_active': self.user_info.get('is_active')
                    },
                    'computing_device_info': {
                        'id': self.computing_device_info.get('id'),
                        'type': self.computing_device_info.get('type'),
                        'brand': self.computing_device_info.get('brand'),
                        'model': self.computing_device_info.get('model'),
                        'serial_number': self.computing_device_info.get('serial_number'),
                        'status': self.computing_device_info.get('status')
                    },
                    'session_info': {
                        'session_start': self.start_time.isoformat() if self.start_time else None,
                        'interface': self.interface,
                        'model_path': self.model_path,
                        'client_id': self.client_id
                    },
                    'detector_output': deteccion_data,
                    'statistics': self.stats.copy()
                }
            }
            
            response = requests.post(
                url, 
                json=payload, 
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.detections_sent += 1
                    self.stats['last_detection'] = datetime.now().isoformat()
                    
                    # Marcar como enviado en respaldo
                    self.marcar_enviado_respaldo(detection_id)
                    
                    print(f"📤 [ENVIADO #{self.detections_sent:03d}] {deteccion_data.get('anomaly_type')} | Severidad: {deteccion_data.get('severity')} | Confianza: {deteccion_data.get('confidence_score', 0):.2f}")
                    return True
                else:
                    print(f"⚠️ [ERROR SERVIDOR] {result.get('message', 'Error desconocido')}")
                    return False
            else:
                print(f"⚠️ [ERROR HTTP] {response.status_code} - Guardado en respaldo local")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"⚠️ [SIN CONEXIÓN] Guardado en respaldo local")
            return False
        except requests.exceptions.Timeout:
            print(f"⚠️ [TIMEOUT] Guardado en respaldo local")
            return False
        except Exception as e:
            print(f"⚠️ [ERROR] {e} - Guardado en respaldo local")
            return False
    
    def guardar_respaldo_local(self, detection_id, deteccion_data):
        """Guarda la detección en respaldo local SQLite"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO detections_backup 
                (detection_id, user_id, client_id, timestamp, anomaly_type, 
                 severity, confidence_score, source_ip, destination_ip, 
                 source_port, destination_port, protocol, raw_data, sent_to_server)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                self.user_id,
                self.client_id,
                datetime.now().isoformat(),
                deteccion_data.get('anomaly_type'),
                deteccion_data.get('severity'),
                deteccion_data.get('confidence_score'),
                deteccion_data.get('source_ip'),
                deteccion_data.get('destination_ip'),
                deteccion_data.get('source_port'),
                deteccion_data.get('destination_port'),
                deteccion_data.get('protocol'),
                json.dumps(deteccion_data, ensure_ascii=False),
                False
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error guardando en respaldo local: {e}")
    
    def marcar_enviado_respaldo(self, detection_id):
        """Marca una detección como enviada en el respaldo"""
        try:
            conn = sqlite3.connect(self.local_backup_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE detections_backup 
                SET sent_to_server = ? 
                WHERE detection_id = ?
            ''', (True, detection_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error marcando como enviado: {e}")
    
    def parsear_salida_detector(self, linea):
        """
        Parsea la salida del detector.py para extraer información de detecciones
        Maneja múltiples formatos de salida
        """
        try:
            # Limpiar códigos ANSI y espacios
            linea_limpia = re.sub(r'\x1b\[[0-9;]*m', '', linea.strip())
            
            if not linea_limpia:
                return None
            
            # Actualizar estadísticas básicas
            self.stats['total_packets'] += 1
            
            # Patrón principal: timestamp [status] IP:port -> IP:port (protocol) - Prob: X.XX
            patron_principal = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(.*?)\]\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+\((\w+)\)\s+-\s+Prob:\s+([\d\.]+)'
            
            match = re.search(patron_principal, linea_limpia)
            
            if match:
                timestamp_str, status, src_ip, src_port, dst_ip, dst_port, protocol, probability = match.groups()
                
                # Clasificar el estado
                status_upper = status.upper()
                confidence = float(probability)
                
                # Solo procesar anomalías (no-normal)
                if 'NORMAL' in status_upper:
                    self.stats['normal_packets'] += 1
                    return None
                
                # Es una anomalía
                self.stats['anomaly_packets'] += 1
                
                # Determinar tipo de anomalía y severidad
                anomaly_type = 'Unknown Anomaly'
                severity = 'medium'
                
                if any(word in status_upper for word in ['ATAQUE', 'ATTACK']):
                    self.stats['attacks_detected'] += 1
                    severity = 'high'
                    
                    if 'SCAN' in status_upper or 'PORT' in status_upper:
                        anomaly_type = 'Port Scan Attack'
                    elif any(word in status_upper for word in ['DOS', 'DDOS']):
                        anomaly_type = 'DDoS Attack'
                        severity = 'critical'
                    elif 'WEB' in status_upper:
                        anomaly_type = 'Web Attack'
                    elif 'SQL' in status_upper:
                        anomaly_type = 'SQL Injection Attack'
                        severity = 'critical'
                    elif any(word in status_upper for word in ['BRUTE', 'FORCE']):
                        anomaly_type = 'Brute Force Attack'
                    elif 'INFILTRACION' in status_upper:
                        anomaly_type = 'Infiltration Attack'
                        severity = 'critical'
                    else:
                        anomaly_type = 'Generic Attack'
                        
                elif any(word in status_upper for word in ['SOSPECHOSO', 'SUSPICIOUS']):
                    anomaly_type = 'Suspicious Activity'
                    severity = 'medium'
                elif 'ANOMALIA' in status_upper:
                    anomaly_type = 'Network Anomaly'
                    severity = 'low'
                
                # Ajustar severidad según confianza
                if confidence >= 0.9:
                    if severity == 'low':
                        severity = 'medium'
                    elif severity == 'medium':
                        severity = 'high'
                elif confidence < 0.5 and severity == 'high':
                    severity = 'medium'
                
                return {
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'source_port': int(src_port),
                    'destination_port': int(dst_port),
                    'protocol': protocol,
                    'anomaly_type': anomaly_type,
                    'severity': severity,
                    'confidence_score': confidence,
                    'original_status': status,
                    'timestamp_original': timestamp_str,
                    'raw_line': linea_limpia
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error parseando línea del detector: {e}")
            return None
    
    def mostrar_estadisticas_periodicas(self):
        """Muestra estadísticas cada cierto tiempo"""
        if self.lines_processed > 0 and self.lines_processed % 50 == 0:
            tiempo_transcurrido = (datetime.now() - self.start_time).total_seconds()
            pps = self.stats['total_packets'] / tiempo_transcurrido if tiempo_transcurrido > 0 else 0
            
            print(f"\n📊 [ESTADÍSTICAS] Líneas: {self.lines_processed} | Paquetes: {self.stats['total_packets']} | " + 
                  f"Anomalías: {self.stats['anomaly_packets']} | Enviadas: {self.detections_sent} | " + 
                  f"PPS: {pps:.1f}")
    
    def enviar_deteccion_inicial(self):
        """Envía una detección inicial indicando el inicio de sesión"""
        deteccion_inicial = {
            'anomaly_type': 'User Session Started',
            'severity': 'low',
            'confidence_score': 1.0,
            'source_ip': '127.0.0.1',
            'destination_ip': '127.0.0.1',
            'source_port': 0,
            'destination_port': 0,
            'protocol': 'SYSTEM',
            'original_status': 'SESSION_START',
            'timestamp_original': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'raw_line': f'Sistema iniciado para usuario {self.user_info.get("username")}'
        }
        
        success = self.enviar_deteccion_servidor(deteccion_inicial)
        if success:
            print("✅ Detección inicial enviada correctamente")
        else:
            print("⚠️ Detección inicial guardada en respaldo local")
    
    def iniciar_detector_proceso(self):
        """Inicia el proceso detector.py y procesa su salida en tiempo real"""
        try:
            # 1. Obtener información del usuario desde PostgreSQL
            print("🔄 Paso 1: Obteniendo información del usuario...")
            if not self.obtener_informacion_usuario():
                raise Exception("No se pudo obtener la información del usuario desde PostgreSQL")
            
            # 2. Verificar archivos necesarios
            print("🔄 Paso 2: Verificando archivos...")
            if not os.path.exists('detector.py'):
                raise FileNotFoundError("El archivo detector.py no se encuentra en el directorio actual")
            
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"El modelo ML no se encuentra: {self.model_path}")
            
            # 3. Registrar inicio de sesión
            self.start_time = datetime.now()
            
            # 4. Enviar detección inicial
            print("🔄 Paso 3: Enviando detección inicial...")
            self.enviar_deteccion_inicial()
            
            # 5. Mostrar información de inicio
            print("\n" + "="*80)
            print("🚀 INICIANDO DETECTOR DE TRÁFICO DE RED")
            print("="*80)
            print(f"👤 Usuario: {self.user_info.get('first_name')} {self.user_info.get('last_name')} (@{self.user_info.get('username')})")
            print(f"💻 Dispositivo: {self.computing_device_info.get('brand')} {self.computing_device_info.get('model')}")
            print(f"🔢 Serial: {self.computing_device_info.get('serial_number')}")
            print(f"🌐 Interfaz de red: {self.interface}")
            print(f"🤖 Modelo ML: {self.model_path}")
            print(f"🎯 Client ID: {self.client_id}")
            print(f"🕐 Inicio: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("="*80)
            print("📡 SALIDA DEL DETECTOR EN TIEMPO REAL:")
            print("="*80)
            
            # 6. Preparar comando del detector
            cmd = [
                sys.executable, 'detector.py',
                '--model', self.model_path,
                '--interface', self.interface,
                '--duration', '0',  # Duración infinita
                '--verbose'
            ]
            
            print(f"🔧 Ejecutando: {' '.join(cmd)}\n")
            
            # 7. Iniciar el proceso detector.py
            self.detector_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.running = True
            
            # 8. Procesar salida en tiempo real
            try:
                while self.running and self.detector_process.poll() is None:
                    linea = self.detector_process.stdout.readline()
                    
                    if not linea:
                        break
                    
                    linea = linea.strip()
                    if linea:
                        self.lines_processed += 1
                        
                        # MOSTRAR TODA LA SALIDA DEL DETECTOR (PRINCIPAL FUNCIONALIDAD)
                        print(f"[DETECTOR] {linea}")
                        
                        # Intentar parsear y procesar detecciones
                        deteccion = self.parsear_salida_detector(linea)
                        if deteccion:
                            # Solo enviar anomalías significativas
                            if deteccion.get('confidence_score', 0) >= 0.3:
                                self.enviar_deteccion_servidor(deteccion)
                        
                        # Mostrar estadísticas periódicamente
                        self.mostrar_estadisticas_periodicas()
                        
            except KeyboardInterrupt:
                print("\n🛑 Interrupción por teclado detectada...")
                self.detener()
                return
                
            # 9. Proceso terminado naturalmente
            if self.detector_process.poll() is not None:
                exit_code = self.detector_process.returncode
                if exit_code == 0:
                    print(f"\n✅ Detector terminado normalmente")
                else:
                    print(f"\n⚠️ Detector terminado con código de error: {exit_code}")
                
        except FileNotFoundError as e:
            print(f"\n❌ Archivo no encontrado: {e}")
            print("💡 Verifica que detector.py y el modelo estén en las rutas correctas")
        except Exception as e:
            print(f"\n❌ Error iniciando detector: {e}")
            raise
    
    def detener(self):
        """Detiene el detector y muestra estadísticas finales"""
        try:
            print(f"\n🛑 Deteniendo detector...")
            self.running = False
            
            # Detener proceso si está corriendo
            if self.detector_process and self.detector_process.poll() is None:
                print("🔄 Terminando proceso detector.py...")
                self.detector_process.terminate()
                
                # Esperar que termine
                try:
                    self.detector_process.wait(timeout=15)
                    print("✅ Proceso detector.py terminado correctamente")
                except subprocess.TimeoutExpired:
                    print("⚠️ Timeout esperando terminación, forzando cierre...")
                    self.detector_process.kill()
                    self.detector_process.wait()
                    print("✅ Proceso forzado a terminar")
            
            # Calcular tiempo total
            if self.start_time:
                tiempo_total = datetime.now() - self.start_time
                tiempo_str = str(tiempo_total).split('.')[0]  # Sin microsegundos
            else:
                tiempo_str = "Desconocido"
            
            # Mostrar estadísticas finales
            print("\n" + "="*70)
            print("📊 ESTADÍSTICAS FINALES DE LA SESIÓN")
            print("="*70)
            print(f"👤 Usuario: {self.user_info.get('username') if self.user_info else 'N/A'}")
            print(f"💻 Dispositivo: {self.computing_device_info.get('brand') if self.computing_device_info else 'N/A'} " + 
                  f"{self.computing_device_info.get('model') if self.computing_device_info else ''}")
            print(f"⏱️ Tiempo de ejecución: {tiempo_str}")
            print(f"📝 Líneas procesadas: {self.lines_processed:,}")
            print(f"📦 Total de paquetes: {self.stats['total_packets']:,}")
            print(f"✅ Paquetes normales: {self.stats['normal_packets']:,}")
            print(f"⚠️ Anomalías detectadas: {self.stats['anomaly_packets']:,}")
            print(f"🚨 Ataques identificados: {self.stats['attacks_detected']:,}")
            print(f"📤 Detecciones enviadas: {self.detections_sent:,}")
            print(f"💾 Respaldo local: {self.local_backup_db}")
            
            if self.stats['last_detection']:
                print(f"🕐 Última detección: {self.stats['last_detection']}")
            
            print("="*70)
            print("✅ Sesión finalizada correctamente")
                    
        except Exception as e:
            print(f"❌ Error durante la detención: {e}")

def main():
    """Función principal del detector integrado"""
    import argparse
    
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(
        description='Detector Integrado Federado - Versión Completa',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python detector_integrado.py --user-id 1 --interface "Wi-Fi" --model "model/modelo_rf.pkl"
  python detector_integrado.py --user-id 2 --interface "Ethernet" --model "model/modelo_rf.pkl"
  
Requisitos:
  - main_prueba.py ejecutándose en localhost:5000
  - PostgreSQL con datos del usuario
  - detector.py en el directorio actual
  - Modelo ML en la ruta especificada
        """
    )
    
    parser.add_argument('--user-id', type=int, required=True, 
                       help='ID del usuario en PostgreSQL')
    parser.add_argument('--interface', required=True, 
                       help='Interfaz de red a monitorear (ej: "Wi-Fi", "Ethernet")')
    parser.add_argument('--model', required=True, 
                       help='Ruta al modelo de Machine Learning')
    
    args = parser.parse_args()
    
    # Mostrar información inicial
    print("🛡️ DETECTOR INTEGRADO FEDERADO - VERSIÓN COMPLETA")
    print("=" * 60)
    print(f"🆔 User ID: {args.user_id}")
    print(f"🌐 Interfaz: {args.interface}")
    print(f"🤖 Modelo: {args.model}")
    print("=" * 60)
    print("⚠️ REQUISITOS:")
    print("   • main_prueba.py ejecutándose en localhost:5000")
    print("   • PostgreSQL configurado con datos del usuario")
    print("   • detector.py en el directorio actual")
    print("   • Modelo ML disponible")
    print("=" * 60)
    print("🚀 Iniciando detector...")
    print("=" * 60)
    
    # Crear instancia del detector
    detector = DetectorFederado(
        user_id=args.user_id,
        interface=args.interface,
        model_path=args.model
    )
    
    try:
        # Iniciar el detector
        detector.iniciar_detector_proceso()
        
    except KeyboardInterrupt:
        print("\n🛑 Detenido por el usuario (Ctrl+C)")
        detector.detener()
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        detector.detener()
        sys.exit(1)

if __name__ == "__main__":
    main()