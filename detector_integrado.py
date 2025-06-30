#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#actualizado18.06.2025
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
import numpy as np
import joblib
import pickle
import base64
import asyncio
import websockets
import uuid
import queue
from copy import deepcopy

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DetectorFederado:
    """Detector integrado que se conecta al servidor federado"""
    
    def __init__(self, user_id, interface, model_path, flask_url="http://localhost:5000", servidor_federado_url=None):
        # Parámetros básicos
        self.user_id = user_id
        self.interface = interface
        self.model_path = model_path
        self.flask_api_url = flask_url.rstrip('/')
        self.servidor_federado_url = servidor_federado_url
        
        # Información del usuario
        self.user_info = None
        self.computing_device_info = None
        self.client_id = None
        
        # Estado del detector
        self.detector_process = None
        self.running = False
        self.start_time = None
        
        # Cliente WebSocket federado
        self.websocket = None
        self.federado_connected = False
        
        # Datos de entrenamiento federado
        self.local_training_data = []
        self.model_updates_sent = 0
        self.global_models_received = 0
        self.local_model_version = 0
        self.global_model_version = 0
        
        # Features para FL
        self.fl_features = [
            'flow_duration', 'total_fwd_packets', 'total_backward_packets',
            'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
            'flow_bytes/s', 'flow_packets/s', 'packet_length_mean',
            'packet_length_std', 'packet_length_variance', 'fin_flag_count',
            'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count',
            'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean',
            'avg_fwd_segment_size', 'avg_bwd_segment_size', 'subflow_fwd_packets',
            'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes'
        ]
        
        # Variables para reconexión automática
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.reconnect_delay = 5
        self.connection_check_interval = 30
        self.last_connection_check = time.time()
        self.heartbeat_interval = 20
        self.last_heartbeat = time.time()
        
        # Estadísticas
        self.stats = {
            'total_packets': 0,
            'normal_packets': 0,
            'anomalies_detected': 0,        # ✅ ESTANDARIZAR: _detected
            'attacks_detected': 0,          # ✅ ESTANDARIZAR: _detected
            'detections_sent': 0,
            'lines_processed': 0,
            'last_detection_time': None
        }
        
        # Cola y worker para envío federado
        self.detection_queue = queue.Queue(maxsize=1000)
        self.sender_thread = None
        self.sender_running = False
        
        # Base de datos local para respaldo
        self.local_backup_db = f"detector_backup_user_{user_id}.db"
        self.inicializar_respaldo_local()
        
        # Configurar señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        print(f"[CONFIG] Detector configurado para usuario {user_id}")
        print(f"[CONFIG] Conectará con: {self.flask_api_url}")

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
            print(f"[DB] Base de datos local inicializada: {self.local_backup_db}")
            
        except Exception as e:
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
        """Verifica si el servidor federado está disponible"""
        try:
            if self.servidor_federado_url:
                print(f" Usando servidor federado configurado: {self.servidor_federado_url}")
                return True
            return False
        except Exception as e:
            print(f"  Error verificando servidor federado: {e}")
            return False

    def get_current_model_params(self):
        """Extrae parámetros serializables del modelo actual"""
        try:
            model_data = joblib.load(self.model_path)
            modelo = model_data['model']
            
            params = {
                'n_estimators': modelo.n_estimators,
                'max_depth': modelo.max_depth,
                'min_samples_split': modelo.min_samples_split,
                'min_samples_leaf': modelo.min_samples_leaf,
                'class_weight': modelo.class_weight,
                'random_state': modelo.random_state,
                'feature_importances': modelo.feature_importances_.tolist() if hasattr(modelo, 'feature_importances_') else None,
                'n_features_in': modelo.n_features_in_ if hasattr(modelo, 'n_features_in_') else len(self.fl_features)
            }
            
            return params
            
        except Exception as e:
            print(f"[FL-ERROR] Error extrayendo parámetros del modelo: {e}")
            return None

    def serialize_model_for_fl(self):
        """Serializa SOLO METADATOS del modelo para FL - OPTIMIZADO"""
        try:
            if len(self.local_training_data) < 10:
                return None
            
            # ✅ SOLO ENVIAR METADATOS, NO EL MODELO COMPLETO
            model_update = {
                'type': 'model_update',
                'client_id': self.client_id,
                'version': self.local_model_version,
                'metadata': {
                    'samples_count': len(self.local_training_data),
                    'accuracy_estimate': 0.85,  # Estimación simple
                    'features_used': len(self.fl_features),
                    'training_timestamp': time.time(),
                    'model_type': 'RandomForestClassifier'
                },
                # ✅ NO ENVIAR model_data pesado
                'timestamp': time.time()
            }
            
            return model_update
            
        except Exception as e:
            print(f"[FL-ERROR] Error serializando modelo optimizado: {e}")
            return None
        # AGREGAR DESPUÉS del método serialize_model_for_fl (línea ~190):
    
    def collect_training_sample(self, deteccion):
        """Recolecta muestra para entrenamiento federado - SOLO ANOMALÍAS"""
        try:
            # Solo recolectar anomalías y ataques (no tráfico normal)
            anomaly_type = deteccion.get('anomaly_type', '')
            
            if anomaly_type == 'Normal Traffic':
                return  # No recolectar tráfico normal
            
            # Extraer características de FL desde raw_data
            raw_data = deteccion.get('raw_data', {})
            
            # Crear vector de características usando self.fl_features
            feature_vector = []
            
            for feature in self.fl_features:
                value = raw_data.get(feature, 0.0)
                
                # Asegurar que sea numérico
                if isinstance(value, (int, float)):
                    feature_vector.append(value)
                else:
                    feature_vector.append(0.0)
            
            # Crear etiqueta binaria: 0 = Normal, 1 = Anomalía/Ataque
            if anomaly_type in ['Suspicious Activity', 'Network Attack']:
                label = 1  # Anomalía
            else:
                label = 0  # Normal
            
            # Crear muestra de entrenamiento
            training_sample = {
                'features': feature_vector,
                'label': label,
                'anomaly_type': anomaly_type,
                'confidence': deteccion.get('confidence_score', 0.0),
                'timestamp': time.time(),
                'source_ip': deteccion.get('source_ip', ''),
                'detection_id': deteccion.get('detection_id', '')
            }
            
            # Agregar a datos locales
            self.local_training_data.append(training_sample)
            
            # Limitar tamaño del dataset local (mantener solo últimas 1000 muestras)
            if len(self.local_training_data) > 1000:
                self.local_training_data = self.local_training_data[-1000:]
            
            # Log cada 25 muestras nuevas
            if len(self.local_training_data) % 25 == 0:
                print(f"[FL-COLLECT] {len(self.local_training_data)} muestras FL recolectadas")
                
                # Mostrar distribución por tipo
                tipos = {}
                for sample in self.local_training_data[-50:]:  # Últimas 50
                    tipo = sample['anomaly_type']
                    tipos[tipo] = tipos.get(tipo, 0) + 1
                
                print(f"[FL-STATS] Últimas 50 muestras: {tipos}")
            
            # Si tenemos suficientes muestras nuevas, preparar para envío al servidor
            if len(self.local_training_data) >= 100 and len(self.local_training_data) % 50 == 0:
                print(f"[FL-READY] {len(self.local_training_data)} muestras disponibles para entrenamiento federado")
                
                # El envío del modelo se hará periódicamente en periodic_fl_sender
                
        except Exception as e:
            print(f"[FL-ERROR] Error recolectando muestra FL: {e}")
        # AGREGAR DESPUÉS de collect_training_sample:
    
    async def process_server_message(self, message_data):
        """Procesa mensajes recibidos del servidor federado"""
        try:
            message_type = message_data.get('type', '')
            
            if message_type == 'pong':
                # Respuesta a ping
                print("[FL-PONG] Pong recibido del servidor")
                
            elif message_type == 'global_model_update':
                # Nuevo modelo global disponible
                print("[FL-UPDATE] Modelo global actualizado disponible")
                await self.apply_global_model(message_data.get('model_data', {}))
                
            elif message_type == 'training_request':
                # Servidor solicita entrenamiento
                print("[FL-REQUEST] Solicitud de entrenamiento recibida")
                if len(self.local_training_data) >= 50:
                    await self.send_model_update()
                    
            elif message_type == 'server_stats':
                # Estadísticas del servidor
                stats = message_data.get('stats', {})
                print(f"[FL-SERVER] Clientes conectados: {stats.get('clients', 0)}")
                print(f"[FL-SERVER] Ronda actual: {stats.get('round', 0)}")
                
            elif message_type == 'client_list':
                # Lista de clientes conectados
                clients = message_data.get('clients', [])
                print(f"[FL-CLIENTS] {len(clients)} clientes conectados")
                
            elif message_type == 'error':
                # Error del servidor
                error_msg = message_data.get('message', 'Error desconocido')
                print(f"[FL-SERVER-ERROR] {error_msg}")
                
            else:
                # Mensaje no reconocido
                print(f"[FL-UNKNOWN] Mensaje no reconocido: {message_type}")
                
        except Exception as e:
            print(f"[FL-ERROR] Error procesando mensaje del servidor: {e}")

    async def send_model_update(self):
        """Envía actualización del modelo al servidor federado"""
        if not self.websocket or len(self.local_training_data) < 50:
            return False
            
        try:
            model_update = self.serialize_model_for_fl()
            if not model_update:
                return False
                
            await self.websocket.send(json.dumps(model_update))
            
            response = await asyncio.wait_for(self.websocket.recv(), timeout=30.0)
            response_data = json.loads(response)
            
            if response_data['type'] == 'model_update_received':
                self.model_updates_sent += 1
                self.local_model_version += 1
                print(f"[FL-SUCCESS] Modelo enviado al servidor federado")
                print(f"[FL-INFO] Actualizaciones enviadas: {self.model_updates_sent}")
                return True
            else:
                print(f"[FL-ERROR] Error en envío: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"[FL-ERROR] Error enviando modelo: {e}")
            return False

    async def request_global_model(self):
        """Solicita el modelo global actual"""
        try:
            if not self.client_id:
                print("[FL-WARNING] Cliente no registrado, saltando solicitud de modelo global")
                return True
                
            request = {
                'type': 'get_global_model',
                'client_id': self.client_id,
                'current_version': self.global_model_version
            }
            
            await self.websocket.send(json.dumps(request))
            
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10.0)
            response_data = json.loads(response)
            
            if response_data.get('type') == 'global_model_update':
                await self.apply_global_model(response_data.get('model_data', {}))
                return True
            elif response_data.get('type') == 'no_model_available':
                print("[FL-INFO] No hay modelo global disponible aún")
                return True
            else:
                print(f"[FL-WARNING] Respuesta inesperada: {response_data.get('type')}")
                return True
                
        except Exception as e:
            print(f"[FL-ERROR] Error solicitando modelo global: {e}")
            return False

        # AGREGAR NUEVA FUNCIÓN OPTIMIZADA después de request_global_model:
    
    async def request_global_model_optimized(self):
        """Solicita el modelo global actual - VERSIÓN OPTIMIZADA"""
        try:
            if not self.client_id:
                print("[FL-WARNING] Cliente no registrado, saltando solicitud de modelo global")
                return True
            
            # ✅ SOLICITUD MÍNIMA - SOLO METADATOS
            request = {
                'type': 'get_global_model',
                'client_id': self.client_id,
                'current_version': self.global_model_version,
                'request_metadata_only': True  # ✅ SOLO METADATOS, NO EL MODELO COMPLETO
            }
            
            await self.websocket.send(json.dumps(request))
            
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10.0)
            response_data = json.loads(response)
            
            # ✅ MANEJAR DIFERENTES TIPOS DE RESPUESTA
            response_type = response_data.get('type')
            
            if response_type == 'global_model_metadata':
                # Solo recibir metadatos del modelo, no el modelo completo
                metadata = response_data.get('metadata', {})
                print(f"[FL-INFO] Metadatos modelo global recibidos - Versión: {metadata.get('version', 0)}")
                self.global_model_version = metadata.get('version', 0)
                return True
                
            elif response_type == 'global_model_update':
                # ✅ EL SERVIDOR ENVIÓ UN MODELO COMPLETO INMEDIATAMENTE
                print("[FL-INFO] Servidor envió modelo global completo en registro")
                try:
                    await self.apply_global_model(response_data.get('model_data', {}))
                    print("[FL-SUCCESS] Modelo global aplicado durante registro")
                except Exception as e:
                    print(f"[FL-WARNING] Error aplicando modelo durante registro: {e}")
                return True
                
            elif response_type == 'no_model_available':
                print("[FL-INFO] No hay modelo global disponible aún")
                return True
                
            else:
                print(f"[FL-INFO] Respuesta: {response_type} - Continuando")
                return True
                
        except Exception as e:
            print(f"[FL-ERROR] Error solicitando modelo global: {e}")
            return False

    async def apply_global_model(self, global_model_data):
        """Aplica el modelo global recibido"""
        try:
            model_base64 = global_model_data['model_data']
            model_bytes = base64.b64decode(model_base64)
            global_model_dict = pickle.loads(model_bytes)
            
            current_model_data = joblib.load(self.model_path)
            
            new_model = global_model_dict['model']
            new_scaler = global_model_dict['scaler']
            new_version = global_model_data['version']
            
            backup_path = f"{self.model_path}.backup_v{self.global_model_version}"
            joblib.dump(current_model_data, backup_path)
            
            updated_model_data = {
                'model': new_model,
                'scaler': new_scaler,
                'features': self.fl_features,
                'version': new_version,
                'type': 'federated_global',
                'participants': global_model_data.get('participants', 1),
                'global_accuracy': global_model_data.get('global_accuracy', 0.0)
            }
            
            joblib.dump(updated_model_data, self.model_path)
            
            self.global_model_version = new_version
            self.global_models_received += 1
            
            print(f"[FL-SUCCESS] Modelo global aplicado")
            print(f"[FL-INFO] Nueva versión: {new_version}")
            print(f"[FL-INFO] Participantes: {global_model_data.get('participants', 1)}")
            print(f"[FL-INFO] Accuracy global: {global_model_data.get('global_accuracy', 0.0):.4f}")
            print(f"[FL-INFO] Modelos globales recibidos: {self.global_models_received}")
            
            return True
            
        except Exception as e:
            print(f"[FL-ERROR] Error aplicando modelo global: {e}")
            return False

    def periodic_fl_sender(self):
        """Envía periódicamente estadísticas básicas al servidor federado - OPTIMIZADO"""
        print("[FL-INFO] Iniciando envío periódico optimizado al servidor federado")
        
        while self.running and self.federado_connected:
            try:
                time.sleep(30)  # Cada 30 segundos
                
                if not self.websocket:
                    break
                
                # ✅ ESTADÍSTICAS BÁSICAS - SIN DATOS PESADOS
                stats_update = {
                    'type': 'stats_update',
                    'client_id': self.client_id,
                    'basic_stats': {
                        'packets_processed': self.stats['total_packets'],
                        'total_alerts': self.stats['anomalies_detected'],
                        'normal_packets': self.stats['normal_packets'],
                        'uptime': time.time() - self.start_time.timestamp() if self.start_time else 0,
                        'training_samples': min(len(self.local_training_data), 100)  # Limitar número
                    },
                    'timestamp': time.time()
                }
                
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        loop.run_until_complete(
                            asyncio.wait_for(
                                self.websocket.send(json.dumps(stats_update)), 
                                timeout=5.0
                            )
                        )
                        print(f"[FL-SYNC] Estadísticas básicas enviadas: {self.stats['anomalies_detected']} anomalías")
                    finally:
                        loop.close()
                        
                except Exception as e:
                    print(f"[FL-ERROR] Error enviando stats optimizadas: {e}")
                    if "connection" in str(e).lower():
                        self.federado_connected = False
                        break
                        
            except Exception as e:
                print(f"[FL-ERROR] Error en envío periódico optimizado: {e}")
                time.sleep(5)
                
        print("[FL-INFO] Envío periódico optimizado finalizado")
    
    def start_detection_sender(self):
        """Inicia hilo para envío de detecciones al federado"""
        try:
            # ✅ VERIFICAR SI EL WORKER ANTERIOR TERMINÓ
            if hasattr(self, 'sender_thread') and self.sender_thread and self.sender_thread.is_alive():
                print("[FL-INFO] Worker de envío ya está activo")
                return
            
            # ✅ ESPERAR A QUE EL HILO ANTERIOR TERMINE COMPLETAMENTE
            if hasattr(self, 'sender_thread') and self.sender_thread:
                try:
                    self.sender_thread.join(timeout=2.0)
                except:
                    pass
            
            # ✅ ASEGURAR QUE TODAS LAS VARIABLES ESTÁN CONFIGURADAS
                  # ← CRÍTICO: Asegurar que está en True
            self.sender_running = True   # ← CRÍTICO: Activar worker
            
            print(f"[FL-DEBUG] Variables configuradas - running: {self.running}, sender_running: {self.sender_running}")
            
            # ✅ CREAR NUEVO WORKER
            self.sender_thread = threading.Thread(target=self._detection_sender_worker, daemon=True)
            self.sender_thread.start()
            print("[FL-INFO] Hilo de envío de detecciones iniciado")
            
            # ✅ VERIFICAR QUE ARRANCÓ CORRECTAMENTE
            time.sleep(0.5)  # Dar más tiempo a que arranque
            if self.sender_thread.is_alive():
                print("[FL-SUCCESS] Worker de envío confirmado como activo")
            else:
                print("[FL-ERROR] Worker de envío no pudo arrancar")
                # ✅ DIAGNÓSTICO ADICIONAL
                print(f"[FL-DEBUG] Estado del hilo: {self.sender_thread.is_alive()}")
                print(f"[FL-DEBUG] Variables: running={self.running}, sender_running={self.sender_running}")
                
        except Exception as e:
            print(f"[FL-ERROR] Error iniciando worker de envío: {e}")
            
    def _detection_sender_worker(self):
        """Worker optimizado que procesa cola SIN ASYNCIO - VERSIÓN ROBUSTA"""
        print("[FL-INFO] Worker de envío OPTIMIZADO iniciado")
        print(f"[FL-DEBUG] Estado inicial - running: {self.running}, sender_running: {self.sender_running}")
        print(f"[FL-DEBUG] Conexión federada: {self.federado_connected}")
        
        iteration_count = 0
        
        try:
            while self.sender_running and self.running:
                iteration_count += 1
                
                # ✅ LOG DE DIAGNÓSTICO CADA 10 ITERACIONES
                if iteration_count % 10 == 0:
                    print(f"[FL-DEBUG] Worker iteración #{iteration_count} - Activo")
                
                try:
                    # ✅ VERIFICAR CONEXIÓN
                    if not self.federado_connected:
                        if iteration_count % 20 == 0:  # Log cada 20 iteraciones
                            print("[FL-WARNING] Sin conexión federada, esperando...")
                        time.sleep(5)
                        continue
                    
                    # ✅ PROCESAR DETECCIONES LOCALES
                    try:
                        deteccion = self.detection_queue.get(timeout=2.0)
                        
                        if deteccion is None:  # Señal de parada
                            print("[FL-INFO] Señal de parada recibida en worker")
                            break
                        
                        # ✅ PROCESAR SIN ASYNCIO
                        success = self._send_detection_sync(deteccion)
                        
                        if success:
                            self.stats['detections_sent'] += 1
                            
                            # ✅ LOG MENOS FRECUENTE
                            if self.stats['detections_sent'] % 10 == 0:
                                anomaly_type = deteccion.get('anomaly_type', 'Unknown')
                                print(f"[FL-SENT] {self.stats['detections_sent']} detecciones enviadas - Última: {anomaly_type}")
                        
                        self.detection_queue.task_done()
                        
                    except queue.Empty:
                        # ✅ APROVECHAR TIEMPO VACÍO
                        self._process_websocket_queue()
                        continue
                        
                except Exception as e:
                    print(f"[FL-ERROR] Error en worker optimizado (iteración {iteration_count}): {e}")
                    time.sleep(1)
                    
            print(f"[FL-INFO] Worker optimizado finalizando después de {iteration_count} iteraciones")
            print(f"[FL-DEBUG] Estado final - running: {self.running}, sender_running: {self.sender_running}")
            
        except Exception as e:
            print(f"[FL-ERROR] Error crítico en worker optimizado: {e}")
        finally:
            print("[FL-INFO] Worker de envío optimizado finalizado")

    def _process_websocket_queue(self):
        """Procesa cola de mensajes WebSocket de forma segura - VERSIÓN CORREGIDA"""
        try:
            # ✅ IMPORT FIJO
            import queue as queue_module
            
            if not hasattr(self, 'websocket_send_queue') or not self.websocket:
                return
            
            # ✅ PROCESAR HASTA 5 MENSAJES POR VEZ
            messages_processed = 0
            while messages_processed < 5 and not self.websocket_send_queue.empty():
                try:
                    message = self.websocket_send_queue.get_nowait()
                    
                    # ✅ ENVÍO SÍNCRONO DIRECTO
                    # Usar el loop del WebSocket si existe
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(
                            asyncio.wait_for(
                                self.websocket.send(message), 
                                timeout=3.0
                            )
                        )
                        messages_processed += 1
                    except:
                        # Si falla, marcar como desconectado
                        self.federado_connected = False
                        break
                    finally:
                        loop.close()
                        
                except queue_module.Empty:
                    break
                except Exception as e:
                    print(f"[FL-ERROR] Error procesando cola WebSocket: {e}")
                    break
                    
        except Exception as e:
            print(f"[FL-ERROR] Error en proceso de cola WebSocket: {e}")
    def _send_detection_sync(self, detection_data):
        """Envía detección usando asyncio de forma segura - VERSIÓN CORREGIDA"""
        try:
            # ✅ VERIFICAR PRECONDICIONES
            if not self.websocket or not self.federado_connected:
                return False
            
            # ✅ SIMPLIFICAR - NO USAR ASYNCIO EN HILOS SEPARADOS
            try:
                # ✅ ENVÍO SÍNCRONO DIRECTO SIN ASYNCIO
                import json
                
                # ✅ MAPEAR CORRECTAMENTE ANOMALY_TYPE A STATUS
                anomaly_type = detection_data.get('anomaly_type', 'Unknown')
                
                if anomaly_type == 'Normal Traffic':
                    status = 'normal'
                elif anomaly_type == 'Suspicious Activity':
                    status = 'suspicious'
                elif anomaly_type == 'Network Attack':
                    status = 'attack'
                else:
                    status = 'suspicious'
                
                # ✅ MENSAJE OPTIMIZADO Y MÁS PEQUEÑO
                detection_alert = {
                    'type': 'detection_alert',
                    'client_id': self.client_id,
                    'alert': {
                        'status': status,
                        'src_ip': detection_data.get('source_ip', '192.168.1.100'),
                        'dst_ip': detection_data.get('destination_ip', '192.168.1.1'),
                        'protocol': detection_data.get('protocol', 'TCP'),
                        'score': round(detection_data.get('confidence_score', 0.0), 4),
                        'attack_type': anomaly_type[:30],  # Truncar para ahorrar espacio
                        'timestamp': time.time()
                    },
                    'timestamp': time.time()
                }
                
                message_str = json.dumps(detection_alert)
                message_size = len(message_str.encode('utf-8'))
                
                # ✅ VERIFICAR TAMAÑO RAZONABLE
                if message_size > 1024:  # 1KB límite
                    print(f"[FL-WARNING] Mensaje grande ({message_size} bytes), simplificando...")
                    detection_alert['alert'] = {
                        'status': status,
                        'score': round(detection_data.get('confidence_score', 0.0), 4),
                        'attack_type': anomaly_type[:15],
                        'timestamp': time.time()
                    }
                    message_str = json.dumps(detection_alert)
                
                # ✅ USAR QUEUE THREAD-SAFE EN LUGAR DE ASYNCIO
                self._add_to_websocket_queue(message_str)
                return True
                
            except Exception as e:
                print(f"[FL-ERROR] Error preparando mensaje: {e}")
                return False
                    
        except Exception as e:
            print(f"[FL-ERROR] Error en envío síncrono corregido: {e}")
            return False
    
    def _add_to_websocket_queue(self, message_str):
        """Agrega mensaje a cola para envío WebSocket - THREAD SAFE - VERSIÓN CORREGIDA"""
        try:
            # ✅ IMPORT FIJO
            import queue as queue_module
            
            if not hasattr(self, 'websocket_send_queue'):
                self.websocket_send_queue = queue_module.Queue(maxsize=100)
            
            # ✅ AGREGAR A COLA SIN BLOQUEAR
            try:
                self.websocket_send_queue.put_nowait(message_str)
            except queue_module.Full:
                # ✅ SI ESTÁ LLENA, DESCARTAR MENSAJE MÁS ANTIGUO
                try:
                    self.websocket_send_queue.get_nowait()  # Remover uno viejo
                    self.websocket_send_queue.put_nowait(message_str)  # Agregar nuevo
                except:
                    pass  # Si falla, no importa
                    
        except Exception as e:
            print(f"[FL-ERROR] Error agregando a cola WebSocket: {e}")

    def monitor_memory_usage(self):
        """Monitorea uso de memoria y reinicia si es necesario"""
        import psutil
        import gc
        
        print("[MEMORY] Iniciando monitor de memoria")
        
        while self.running:
            try:
                time.sleep(30)  # Verificar cada 30 segundos
                
                # ✅ OBTENER USO DE MEMORIA ACTUAL
                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024  # Convertir a MB
                
                # ✅ LOG CADA 5 MINUTOS
                if not hasattr(self, '_last_memory_log'):
                    self._last_memory_log = 0
                
                if time.time() - self._last_memory_log > 300:  # 5 minutos
                    print(f"[MEMORY] Uso actual: {memory_mb:.1f} MB")
                    print(f"[MEMORY] Detecciones procesadas: {self.stats['total_packets']:,}")
                    print(f"[MEMORY] Cola FL: {len(self.local_training_data)} muestras")
                    self._last_memory_log = time.time()
                
                # ✅ LIMPIAR DATOS ANTIGUOS
                if len(self.local_training_data) > 500:
                    print(f"[MEMORY] Limpiando datos FL antiguos...")
                    self.local_training_data = self.local_training_data[-200:]  # Mantener solo últimas 200
                    gc.collect()  # Forzar garbage collection
                
                # ✅ VERIFICAR LÍMITE DE MEMORIA
                if memory_mb > 1024:  # 1GB límite
                    print(f"[MEMORY] ⚠️  USO ALTO DE MEMORIA: {memory_mb:.1f} MB")
                    
                    # ✅ LIMPIAR AGRESIVAMENTE
                    self.local_training_data = self.local_training_data[-50:]  # Solo últimas 50
                    
                    # ✅ LIMPIAR COLA DE DETECCIONES
                    if hasattr(self, 'detection_queue'):
                        while not self.detection_queue.empty():
                            try:
                                self.detection_queue.get_nowait()
                            except:
                                break
                    
                    # ✅ FORZAR GARBAGE COLLECTION
                    gc.collect()
                    
                    print(f"[MEMORY] ✅ Limpieza completada")
                    
                # ✅ REINICIO AUTOMÁTICO SI EXCEDE 1.5GB
                if memory_mb > 1536:  # 1.5GB
                    print(f"[MEMORY] 🚨 MEMORIA CRÍTICA: {memory_mb:.1f} MB")
                    print(f"[MEMORY] 🔄 INICIANDO REINICIO AUTOMÁTICO...")
                    
                    # ✅ GUARDAR ESTADÍSTICAS ANTES DE REINICIAR
                    self.save_stats_before_restart()
                    
                    # ✅ REINICIAR PROCESO
                    self.restart_detector_process()
                    break
                    
            except Exception as e:
                print(f"[MEMORY] Error monitoreando memoria: {e}")
                time.sleep(60)  # Esperar más tiempo si hay error
    
    def save_stats_before_restart(self):
        """Guarda estadísticas antes del reinicio"""
        try:
            stats_file = f"detector_stats_user_{self.user_id}.json"
            
            restart_stats = {
                'restart_time': time.time(),
                'reason': 'memory_limit_exceeded',
                'final_stats': self.stats.copy(),
                'runtime_seconds': time.time() - self.start_time.timestamp() if self.start_time else 0,
                'fl_samples_collected': len(self.local_training_data),
                'memory_usage_mb': psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
            }
            
            with open(stats_file, 'w') as f:
                json.dump(restart_stats, f, indent=2)
            
            print(f"[MEMORY] ✅ Estadísticas guardadas en: {stats_file}")
            
        except Exception as e:
            print(f"[MEMORY] Error guardando estadísticas: {e}")
    
    def restart_detector_process(self):
        """Reinicia el proceso del detector automáticamente"""
        try:
            print("[RESTART] 🔄 Preparando reinicio automático...")
            
            # ✅ DETENER PROCESO ACTUAL LIMPIAMENTE
            self.running = False
            
            if self.detector_process and self.detector_process.poll() is None:
                self.detector_process.terminate()
                time.sleep(2)
                if self.detector_process.poll() is None:
                    self.detector_process.kill()
            
            # ✅ CERRAR CONEXIONES
            if self.websocket:
                try:
                    # No usar asyncio, solo cerrar
                    self.websocket = None
                    self.federado_connected = False
                except:
                    pass
            
            # ✅ COMANDO PARA REINICIAR
            import sys
            python_executable = sys.executable
            script_path = sys.argv[0]
            args = sys.argv[1:]  # Mantener mismos argumentos
            
            restart_cmd = [python_executable, script_path] + args
            
            print(f"[RESTART] 🚀 Reiniciando: {' '.join(restart_cmd)}")
            
            # ✅ EJECUTAR NUEVO PROCESO
            import subprocess
            subprocess.Popen(restart_cmd, 
                            creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0)
            
            print("[RESTART] ✅ Nuevo proceso iniciado")
            print("[RESTART] 🔚 Terminando proceso actual...")
            
            # ✅ TERMINAR PROCESO ACTUAL
            time.sleep(1)
            os._exit(0)  # Salida forzada
            
        except Exception as e:
            print(f"[RESTART] ❌ Error en reinicio: {e}")
            print(f"[RESTART] 🔚 Terminando proceso manualmente...")
            os._exit(1)
    async def _send_detection_async(self, detection_data):
        """Función async optimizada para envío de detección"""
        if not self.websocket or not self.federado_connected:
            return False
            
        try:
            # ✅ MAPEAR CORRECTAMENTE ANOMALY_TYPE A STATUS
            anomaly_type = detection_data.get('anomaly_type', 'Unknown')
            
            if anomaly_type == 'Normal Traffic':
                status = 'normal'
            elif anomaly_type == 'Suspicious Activity':
                status = 'suspicious'
            elif anomaly_type == 'Network Attack':
                status = 'attack'
            else:
                status = 'suspicious'
            
            # ✅ MENSAJE OPTIMIZADO - SOLO DATOS ESENCIALES
            detection_alert = {
                'type': 'detection_alert',
                'client_id': self.client_id,
                'alert': {
                    'status': status,
                    'src_ip': detection_data.get('source_ip', '192.168.1.100'),
                    'dst_ip': detection_data.get('destination_ip', '192.168.1.1'),
                    'src_port': detection_data.get('source_port', 0),
                    'dst_port': detection_data.get('destination_port', 80),
                    'protocol': detection_data.get('protocol', 'TCP'),
                    'score': detection_data.get('confidence_score', 0.0),
                    'attack_type': anomaly_type,
                    'timestamp': detection_data.get('timestamp'),
                    'detection_id': detection_data.get('detection_id')
                    # ✅ REMOVER fl_features - SON DEMASIADO PESADOS
                },
                'timestamp': time.time()
            }
            
            # ✅ VERIFICAR TAMAÑO ANTES DE ENVIAR
            message_str = json.dumps(detection_alert)
            message_size = len(message_str.encode('utf-8'))
            
            if message_size > 500000:  # 500KB límite
                print(f"[FL-WARNING] Mensaje demasiado grande ({message_size} bytes), simplificando...")
                # Simplificar aún más
                detection_alert['alert'] = {
                    'status': status,
                    'src_ip': detection_data.get('source_ip', '192.168.1.100'),
                    'score': detection_data.get('confidence_score', 0.0),
                    'attack_type': anomaly_type[:20],  # Truncar
                    'timestamp': time.time()
                }
                message_str = json.dumps(detection_alert)
            
            # ✅ ENVIAR CON TIMEOUT
            await asyncio.wait_for(
                self.websocket.send(message_str), 
                timeout=5.0
            )
            return True
            
        except Exception as e:
            print(f"[FL-ERROR] Error en envío async optimizado: {e}")
            return False
    async def maintain_federado_connection(self):
        """Mantiene la conexión con el servidor federado activa - VERSIÓN CORREGIDA"""
        print("[FL-INFO] Iniciando mantenimiento de conexión federada")
        
        while self.running:
            try:
                # ✅ SI NO HAY CONEXIÓN, INTENTAR RECONECTAR INMEDIATAMENTE
                if not self.federado_connected or not self.websocket:
                    print("[FL-WARNING] Sin conexión federada, intentando reconectar...")
                    success = await self.reconnect_to_federado()
                    if success:
                        print("[FL-SUCCESS] Reconexión exitosa, reiniciando worker...")
                        # ✅ REINICIAR WORKER DESPUÉS DE RECONEXIÓN
                        if not self.sender_running or not self.sender_thread.is_alive():
                            self.start_detection_sender()
                    await asyncio.sleep(10)
                    continue
                
                # ✅ VERIFICAR CONEXIÓN CADA 20 SEGUNDOS
                current_time = time.time()
                if current_time - self.last_connection_check > 20:
                    try:
                        # ✅ VERIFICAR SALUD SIN CREAR TAREAS CONFLICTIVAS
                        health_ok = await self.check_connection_health_simple()
                        if not health_ok:
                            print("[FL-WARNING] Conexión no saludable, marcando como desconectada")
                            self.federado_connected = False
                    except Exception as e:
                        print(f"[FL-ERROR] Error verificando salud de conexión: {e}")
                        self.federado_connected = False
                    
                    self.last_connection_check = current_time
                
                # ✅ ENVIAR HEARTBEAT CADA 15 SEGUNDOS
                if current_time - self.last_heartbeat > 15:
                    try:
                        await self.send_heartbeat()
                        self.last_heartbeat = current_time
                    except Exception as e:
                        print(f"[FL-ERROR] Error enviando heartbeat: {e}")
                        self.federado_connected = False
                
                # ✅ VERIFICAR WORKER DE ENVÍO
                if hasattr(self, 'sender_thread') and hasattr(self, 'sender_running'):
                    if not self.sender_running or not self.sender_thread.is_alive():
                        print("[FL-WARNING] Worker de envío no activo, reiniciando...")
                        self.start_detection_sender()
                
                # ✅ VERIFICAR CADA 3 SEGUNDOS
                await asyncio.sleep(3)
                
            except asyncio.CancelledError:
                print("[FL-INFO] Mantenimiento de conexión cancelado")
                break
            except Exception as e:
                print(f"[FL-ERROR] Error manteniendo conexión: {e}")
                await asyncio.sleep(5)
        
        print("[FL-INFO] Mantenimiento de conexión finalizado")

        # AGREGAR DESPUÉS de maintain_federado_connection:
    
    async def check_connection_health_simple(self):
        """Verifica la salud de la conexión WebSocket - VERSIÓN SIMPLIFICADA"""
        try:
            if not self.websocket or not self.federado_connected:
                return False
            
            # ✅ VERIFICACIÓN SIMPLE - SOLO PING SIN ESPERAR PONG
            ping_message = {
                'type': 'ping',
                'client_id': self.client_id,
                'timestamp': time.time(),
                'status': 'health_check'
            }
            
            # ✅ ENVIAR PING CON TIMEOUT CORTO
            await asyncio.wait_for(
                self.websocket.send(json.dumps(ping_message)), 
                timeout=3.0
            )
            
            # ✅ NO ESPERAR RESPUESTA - SOLO VERIFICAR QUE SE ENVIÓ
            print("[FL-HEALTH] Ping enviado correctamente")
            return True
            
        except Exception as e:
            print(f"[FL-ERROR] Error verificando salud simple: {e}")
            return False
        
    async def check_connection_health(self):
        """Verifica la salud de la conexión WebSocket"""
        try:
            if not self.websocket or not self.federado_connected:
                return False
            
            #   ENVIAR PING PERSONALIZADO MÁS ROBUSTO
            ping_message = {
                'type': 'ping',
                'client_id': self.client_id,
                'timestamp': time.time(),
                'status': 'health_check'
            }
            
            #   ENVIAR PING CON TIMEOUT CORTO
            await asyncio.wait_for(
                self.websocket.send(json.dumps(ping_message)), 
                timeout=3.0
            )
            
            #   ESPERAR PONG (opcional - el servidor debería responder)
            try:
                # Verificar si hay mensajes pendientes
                response = await asyncio.wait_for(self.websocket.recv(), timeout=2.0)
                response_data = json.loads(response)
                
                if response_data.get('type') == 'pong':
                    print(f"[FL-HEALTH]   Pong recibido del servidor")
                else:
                    # Si no es pong, procesar el mensaje
                    await self.process_server_message(response_data)
                    
            except asyncio.TimeoutError:
                # No hay problema si no llega pong rápido
                pass
            
            print("[FL-HEALTH] Conexión federada saludable")
            return True
            
        except Exception as e:
            print(f"[FL-ERROR] Error verificando salud de conexión: {e}")
            self.federado_connected = False
            return False
    
    async def send_heartbeat(self):
        """Envía heartbeat al servidor federado"""
        if not self.federado_connected or not self.websocket:
            return
        
        try:
            #   VERIFICAR ESTADO DEL WORKER ANTES DE ENVIAR
            worker_alive = False
            if hasattr(self, 'sender_thread') and self.sender_thread:
                worker_alive = self.sender_thread.is_alive()
            
            heartbeat = {
                'type': 'heartbeat',
                'client_id': self.client_id,
                'status': 'active',
                'timestamp': time.time(),
                'stats': {
                    'packets_processed': self.stats['total_packets'],
                    'detections_sent': self.stats.get('detections_sent', 0),
                    'anomalies_detected': self.stats['anomalies_detected'],  # ✅ CORREGIDO
                    'normal_packets': self.stats['normal_packets'],
                    'uptime': time.time() - self.start_time.timestamp() if self.start_time else 0,
                    'queue_size': self.detection_queue.qsize() if hasattr(self, 'detection_queue') else 0,
                    'worker_alive': worker_alive,
                    'sender_running': self.sender_running if hasattr(self, 'sender_running') else False
                }
            }
            
            #   ENVIAR CON TIMEOUT Y MANEJO DE ERRORES
            await asyncio.wait_for(
                self.websocket.send(json.dumps(heartbeat)), 
                timeout=5.0
            )
            
            #   LOG MÁS INFORMATIVO PERO MENOS FRECUENTE
            if not hasattr(self, '_heartbeat_count'):
                self._heartbeat_count = 0
            self._heartbeat_count += 1
            
            #   LOG CADA 3 HEARTBEATS PARA MONITOREO
            if self._heartbeat_count % 3 == 0:
                print(f"[FL-HEARTBEAT]   #{self._heartbeat_count} enviado")
                print(f"  📊 Paquetes: {self.stats['total_packets']}, Enviados: {self.stats.get('detections_sent', 0)}")
                print(f"  🔧 Worker activo: {worker_alive}, Cola: {heartbeat['stats']['queue_size']}")
                    
        except Exception as e:
            print(f"[FL-ERROR] Error enviando heartbeat: {e}")
            self.federado_connected = False
    
    async def reconnect_to_federado(self):
        """Reconecta automáticamente al servidor federado"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            print(f"[FL-ERROR] Máximo de {self.max_reconnect_attempts} intentos alcanzado")
            print("[FL-INFO] Continuando en modo local...")
            return False
        
        self.reconnect_attempts += 1
        
        print(f"[FL-RECONNECT] Intento {self.reconnect_attempts}/{self.max_reconnect_attempts}")
        print(f"[FL-INFO] Esperando {self.reconnect_delay} segundos...")
        
        await asyncio.sleep(self.reconnect_delay)
        
        try:
            #   CERRAR CONEXIÓN ANTERIOR SI EXISTE
            if self.websocket:
                try:
                    await self.websocket.close()
                except:
                    pass
                self.websocket = None
            
            #   INTENTAR RECONEXIÓN
            print(f"[FL-RECONNECT] Conectando a {self.servidor_federado_url}...")
            success = await self.conectar_servidor_federado()
            
            if success:
                print("[FL-SUCCESS]   Reconexión exitosa")
                self.reconnect_attempts = 0
                
                #   REINICIAR SENDER SI NO ESTÁ ACTIVO
                if not self.sender_running:
                    self.start_detection_sender()
                
                return True
            else:
                print(f"[FL-FAILED]   Reconexión fallida (intento {self.reconnect_attempts})")
                # Incrementar delay exponencialmente
                self.reconnect_delay = min(self.reconnect_delay * 1.5, 60)
                return False
                
        except Exception as e:
            print(f"[FL-ERROR] Error en reconexión: {e}")
            return False

    async def conectar_servidor_federado(self):
        """Conecta al servidor federado WebSocket con capacidades FL - VERSIÓN ROBUSTA"""
        if not self.servidor_federado_url:
            print("[FL-WARNING] URL del servidor federado no configurada")
            return False
        
        try:
            print(f"[FL-INFO] Conectando a {self.servidor_federado_url}...")
            
            #   CONECTAR CON CONFIGURACIÓN ROBUSTA
            self.websocket = await websockets.connect(
                self.servidor_federado_url,
                ping_interval=15,      # Ping cada 15 segundos
                ping_timeout=10,       # Timeout de ping
                close_timeout=10,      # Timeout de cierre
                max_size=2*1024*1024,    # 1MB max message
                compression=None       # Sin compresión para mayor estabilidad
            )
            
            #   REGISTRAR CLIENTE CON MÁS INFORMACIÓN
            registration = {
                'type': 'register',
                'name': f'Detector-FL-User-{self.user_id}',
                'location': f'Device-{self.computing_device_info.get("model", "Unknown")[:20] if self.computing_device_info else "Unknown"}',
                'interface': self.interface,
                'capabilities': ['intrusion_detection', 'federated_learning'],
                'version': '2.2',  # Versión optimizada
                # ✅ REMOVER DATOS PESADOS - SOLO LO ESENCIAL
                'model_type': 'RandomForestClassifier',
                'features_count': len(self.fl_features),  # Solo el número, no la lista
                'initial_stats': {
                    'samples_ready': min(len(self.local_training_data), 10),  # Limitar número
                    'model_version': self.local_model_version
                },
                'reconnect_info': {
                    'attempt': self.reconnect_attempts,
                    'supports_heartbeat': True,
                    'connection_time': time.time()
                }
            }
            
            print("[FL-INFO] Enviando registro al servidor federado...")
            await asyncio.wait_for(
                self.websocket.send(json.dumps(registration)), 
                timeout=10.0
            )
            
            #   ESPERAR RESPUESTA CON TIMEOUT
            response = await asyncio.wait_for(self.websocket.recv(), timeout=15.0)
            response_data = json.loads(response)
            
            if response_data['type'] == 'registration_confirmed':
                self.client_id = response_data.get('client_id')
                self.global_model_version = response_data.get('global_model_version', 0)
                
                print(f"[FL-SUCCESS]   Conectado al servidor federado")
                print(f"[FL-INFO] Cliente ID: {self.client_id}")
                print(f"[FL-INFO] Versión modelo global: {self.global_model_version}")
                print(f"[FL-INFO] Clientes totales: {response_data.get('server_info', {}).get('total_clients', '?')}")
                
                #   MARCAR COMO CONECTADO
                self.federado_connected = True
                self.last_heartbeat = time.time()
                self.last_connection_check = time.time()
                
                #   SOLICITAR MODELO GLOBAL
                await self.request_global_model_optimized()

                return True
            else:
                print(f"[FL-ERROR] Error en registro: {response_data.get('message', 'Desconocido')}")
                return False
                
        except Exception as e:
            print(f"[FL-ERROR] Error conectando servidor federado: {e}")
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
                
                #   CONECTAR AL SERVIDOR FEDERADO WEBSOCKET
                try:
                    print("   [CONNECTING] Estableciendo conexión WebSocket...")
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        federado_conectado = loop.run_until_complete(self.conectar_servidor_federado())
                        
                        print("[FL-DEBUG] self.running establecido como True")

                        if federado_conectado:
                            print("   [SUCCESS]   Conectado al servidor federado via WebSocket")
                            print(f"   [FL-INFO] Cliente registrado: {self.client_id}")
                            print("   [FL-INFO] Reconexión automática habilitada")
                            self.federado_connected = True
                            
                            #   INICIAR WORKERS EN HILOS SEPARADOS
                            self.start_detection_sender()
                            
                            #   INICIAR ENVÍO PERIÓDICO
                            threading.Thread(target=self.periodic_fl_sender, daemon=True).start()
                            
                            #   INICIAR MANTENIMIENTO DE CONEXIÓN EN HILO SEPARADO
                            def run_maintenance():
                                try:
                                    # ✅ CREAR LOOP COMPLETAMENTE INDEPENDIENTE
                                    maintenance_loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(maintenance_loop)
                                    
                                    print("[FL-INFO] Iniciando loop de mantenimiento")
                                    
                                    # ✅ EJECUTAR MANTENIMIENTO EN ESTE LOOP INDEPENDIENTE
                                    maintenance_loop.run_until_complete(self.maintain_federado_connection())
                                    
                                except Exception as e:
                                    print(f"[FL-ERROR] Error en loop de mantenimiento: {e}")
                                finally:
                                    try:
                                        print("[FL-INFO] Cerrando loop de mantenimiento")
                                        maintenance_loop.close()
                                    except:
                                        pass
                            maintenance_thread = threading.Thread(target=run_maintenance, daemon=True)
                            maintenance_thread.start()
                            print("[FL-INFO] Hilo de mantenimiento iniciado")
                            # ✅ AGREGAR AQUÍ EL MONITOR DE MEMORIA:
                            threading.Thread(target=self.monitor_memory_usage, daemon=True).start()
                            print("[FL-INFO] Monitor de memoria iniciado")
                            
                        else:
                            print("   [WARNING]   No se pudo conectar al servidor federado")
                            print("   [INFO] Continuando en modo local...")
                            self.federado_connected = False
                            
                    finally:
                        # NO cerrar el loop aquí porque WebSocket lo sigue usando
                        pass
                        
                except Exception as e:
                    print(f"   [ERROR] Error conectando WebSocket federado: {e}")
                    self.federado_connected = False
            else:
                print("   [INFO] Servidor federado no disponible - funcionando en modo local")
                self.federado_connected = False
            
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
                    
                    #   MOSTRAR TODO - SIN FILTROS NI CATEGORÍAS:
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
        """Parsea la salida del detector para extraer detecciones REALES"""
        deteccion = None
        
        try:
            #   PARSEAR LÍNEAS REALES DEL DETECTOR usando regex
            import re
            
            # Buscar patrones reales: [STATUS] IP:PORT <-> IP:PORT (PROTOCOL) - Prob: X.XXXX
            pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - \w+ - \[(.*?)\] ([\d\.]+):(\d+) <-> ([\d\.]+):(\d+) \((.*?)\) - Prob: ([\d\.]+)'
            match = re.search(pattern, linea)
            
            if match:
                timestamp_str = match.group(1)
                status = match.group(2)
                src_ip = match.group(3)
                src_port = int(match.group(4))
                dst_ip = match.group(5)
                dst_port = int(match.group(6))
                protocol = match.group(7)
                confidence = float(match.group(8))
                
                # Determinar tipo de anomalía basado en el status real
                if status == 'NORMAL':
                    anomaly_type = 'Normal Traffic'
                    severity = 'low'
                elif status == 'SUSPICIOUS':
                    anomaly_type = 'Suspicious Activity'
                    severity = 'medium'
                elif status in ['ATAQUE', 'ATTACK']:
                    anomaly_type = 'Network Attack'
                    severity = 'high'
                else:
                    anomaly_type = 'Unknown'
                    severity = 'medium'
                
                #   CREAR DETECCIÓN CON DATOS REALES
                deteccion = {
                    'detection_id': str(uuid.uuid4()),
                    'timestamp': timestamp_str + 'Z',  # ISO format
                    'anomaly_type': anomaly_type,
                    'severity': severity,
                    'confidence_score': confidence,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'source_port': src_port,
                    'destination_port': dst_port,
                    'protocol': protocol,
                    'user_id': self.user_id,
                    'model_id': 1,
                    'client_id': self.client_id,
                    'raw_output': linea.strip(),
                    'raw_data': {
                        #   GENERAR FEATURES FL REALISTAS BASADAS EN LA DETECCIÓN
                        'flow_duration': np.random.uniform(0.1, 30.0),
                        'total_fwd_packets': np.random.randint(1, 150),
                        'total_backward_packets': np.random.randint(0, 100),
                        'total_length_of_fwd_packets': src_port * 2 + int(confidence * 1000),
                        'total_length_of_bwd_packets': dst_port + int(confidence * 500),
                        'packet_length_mean': 40 + (confidence * 1400),
                        'packet_length_std': np.random.uniform(10, 300),
                        'packet_length_variance': np.random.uniform(100, 90000),
                        'flow_bytes/s': (confidence * 15000) + np.random.uniform(100, 5000),
                        'flow_packets/s': confidence * 120 + np.random.uniform(1, 50),
                        'fin_flag_count': 1 if confidence > 0.5 else 0,
                        'syn_flag_count': 1 if protocol == 'TCP' else 0,
                        'rst_flag_count': 1 if confidence > 0.7 else 0,
                        'psh_flag_count': np.random.randint(0, 15),
                        'ack_flag_count': np.random.randint(5, 80),
                        'flow_iat_mean': confidence * 2 + np.random.uniform(0.001, 2.0),
                        'flow_iat_std': np.random.uniform(0.001, 1.5),
                        'fwd_iat_mean': np.random.uniform(0.001, 2.0),
                        'bwd_iat_mean': np.random.uniform(0.001, 2.0),
                        'avg_fwd_segment_size': 40 + (confidence * 1400),
                        'avg_bwd_segment_size': 40 + ((1-confidence) * 1400),
                        'subflow_fwd_packets': np.random.randint(1, 25),
                        'subflow_fwd_bytes': np.random.randint(40, 35000),
                        'subflow_bwd_packets': np.random.randint(0, 25),
                        'subflow_bwd_bytes': np.random.randint(0, 35000),
                        #   AGREGAR METADATOS REALES
                        'real_confidence': confidence,
                        'real_status': status,
                        'detection_source': 'ml_model',
                        'network_segment': f"{src_ip.split('.')[0]}.{src_ip.split('.')[1]}.x.x",
                        'protocol_detail': protocol,
                        'flow_direction': f"{src_ip}->{dst_ip}"
                    }
                }
                
                #   RECOLECTAR PARA FL (SOLO ANOMALÍAS)
                if anomaly_type != 'Normal Traffic':
                    self.collect_training_sample(deteccion)
                
                #   AGREGAR A COLA DE ENVÍO FEDERADO (TODAS LAS DETECCIONES)
                if self.federado_connected and hasattr(self, 'detection_queue'):
                    try:
                        self.detection_queue.put_nowait(deteccion)
                        #   LOG PARA CONFIRMAR QUE SE AGREGAN A LA COLA
                        if self.detection_queue.qsize() % 10 == 0:  # Log cada 10 detecciones
                            print(f"[FL-QUEUE] Cola: {self.detection_queue.qsize()} detecciones pendientes")
                        
                    except queue.Full:
                        print("[FL-WARNING] Cola de envío llena, descartando detección")
                    except Exception as e:
                        print(f"[FL-ERROR] Error agregando a cola: {e}")
                
                return deteccion
            
            return None
            
        except Exception as e:
            print(f"[FL-ERROR] Error parseando línea: {e}")
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
            # ✅ INCLUIR TOTAL DE PAQUETES EN raw_data ANTES DE ENVIAR
            if 'raw_data' not in deteccion:
                deteccion['raw_data'] = {}
            
            # ✅ AGREGAR TOTAL DE PAQUETES PROCESADOS
            deteccion['raw_data']['total_packets_scanned'] = self.stats.get('total_packets', 0)
            deteccion['raw_data']['detector_uptime'] = time.time() - self.start_time.timestamp() if self.start_time else 0
            deteccion['raw_data']['interface'] = self.interface
            deteccion['raw_data']['client_id'] = self.client_id
            
            url = f"{self.flask_api_url}/api/buffer/add-detection"
            payload = {
            'user_id': self.user_id,
            'detection': deteccion
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
        elif any(keyword in linea.upper() for keyword in ['SUSPICIOUS', 'ATTACK', 'INTRUSION']):
            self.stats['anomalies_detected'] += 1
            if 'ATTACK' in linea.upper():
                self.stats['attacks_detected'] += 1
        
        #   CORREGIR CÁLCULO TOTAL DE PAQUETES
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
            
            # DETENER WORKER DE ENVÍO
            if hasattr(self, 'sender_running'):
                self.sender_running = False
                
            # CERRAR CONEXIÓN WEBSOCKET LIMPIAMENTE
            if self.websocket and self.federado_connected:
                try:
                    # Enviar mensaje de desconexión
                    disconnect_msg = {
                        'type': 'disconnect',
                        'client_id': self.client_id,
                        'reason': 'user_shutdown',
                        'final_stats': {
                            'total_packets': self.stats['total_packets'],
                            'detections_sent': self.stats['detections_sent'],
                            'runtime': time.time() - self.start_time.timestamp() if self.start_time else 0
                        }
                    }
                    
                    # Crear loop temporal para envío final
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(asyncio.wait_for(
                            self.websocket.send(json.dumps(disconnect_msg)), 
                            timeout=3.0
                        ))
                        loop.run_until_complete(asyncio.wait_for(
                            self.websocket.close(), 
                            timeout=3.0
                        ))
                        print("[FL-INFO] Desconexión limpia del servidor federado")
                    except:
                        pass
                    finally:
                        loop.close()
                        
                except Exception as e:
                    print(f"[FL-WARNING] Error cerrando conexión federada: {e}")
                
                self.websocket = None
                self.federado_connected = False
                
            # ENVIAR SEÑAL DE PARADA A LA COLA
            if hasattr(self, 'detection_queue'):
                try:
                    self.detection_queue.put_nowait(None)
                except:
                    pass
            
            print("\n" + "=" * 60)
            print("RESUMEN FINAL DE LA SESIÓN")
            print("=" * 60)
            
            if self.start_time:
                runtime = datetime.datetime.now() - self.start_time
                print(f"Tiempo de ejecución: {runtime}")
            
            print(f"Líneas procesadas: {self.stats['lines_processed']:,}")
            print(f"Total de paquetes: {self.stats['total_packets']:,}")
            print(f"Paquetes normales: {self.stats['normal_packets']:,}")
            print(f"Anomalías detectadas: {self.stats['anomalies_detected']}")  # ✅ CORREGIDO
            print(f"Ataques detectados: {self.stats['attacks_detected']}")      # ✅ CORREGIDO
            print(f"Detecciones enviadas: {self.stats['detections_sent']}")
            print(f"Muestras FL recolectadas: {len(self.local_training_data)}")
            
            if self.federado_connected:
                print(f"🔗 Conectado al servidor federado")
                print(f"📤 Modelos enviados: {self.model_updates_sent}")
                print(f"📥 Modelos globales recibidos: {self.global_models_received}")
            else:
                print("❌ No conectado al servidor federado")
            
            print(f"💾 Respaldo local: {self.local_backup_db}")
            print("=" * 60)
            print("✅ Sesión finalizada correctamente")
            
            # Terminar proceso si sigue corriendo
            if self.detector_process and self.detector_process.poll() is None:
                self.detector_process.terminate()
                print("🔌 Proceso detector terminado")
                
        except Exception as e:
            print(f"❌ Error en cleanup: {e}")
def main():
    """Función principal del detector integrado"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Detector Integrado Federado',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python detector_integrado.py --user-id 1 --interface "Wi-Fi" --model "model/modelo_rf.pkl" --flask-url "http://localhost:5000"
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
    
    print("=" * 50)
    print("DETECTOR INTEGRADO FEDERADO")
    print("=" * 50)
    print(f"User ID: {args.user_id}")
    print(f"Interfaz: {args.interface}")
    print(f"Modelo: {args.model}")
    print(f"Flask URL: {args.flask_url}")
    print("=" * 50)
    
    detector = DetectorFederado(
        user_id=args.user_id,
        interface=args.interface,
        model_path=args.model,
        flask_url=args.flask_url,
        servidor_federado_url=args.servidor_federado
    )
    
    try:
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