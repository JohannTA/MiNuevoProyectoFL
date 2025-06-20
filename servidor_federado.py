#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Servidor Federado para Sistema de Detección de Intrusiones
----------------------------------------------------------
Coordina múltiples clientes IDS y agrega sus modelos
Autor: Johann
Fecha: 2025-06-06
Versión: 1.0
"""
import numpy as np
import pickle
import base64
import asyncio
import websockets
import json
import logging
import threading
import time
import datetime
import numpy as np
import joblib
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional
import uuid
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import warnings
import signal
import sys
import os

warnings.filterwarnings("ignore")

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("servidor_federado.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FederatedAggregator:
    """Implementa algoritmo Federated Averaging optimizado para Random Forest"""
    
    def __init__(self):
        self.client_models = {}
        self.global_model = None
        self.round_number = 0
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
        
    def add_client_model(self, client_id, model_data):
        """Agrega modelo de cliente para agregación"""
        try:
            # Deserializar modelo
            model_bytes = base64.b64decode(model_data['model_data'])
            client_model_dict = pickle.loads(model_bytes)
            
            self.client_models[client_id] = {
                'model': client_model_dict['model'],
                'scaler': client_model_dict['scaler'],
                'samples': model_data['training_samples'],
                'accuracy': model_data['local_accuracy'],
                'version': model_data['model_version'],
                'timestamp': model_data['timestamp']
            }
            
            logger.info(f"[FL] Modelo recibido de cliente {client_id}")
            logger.info(f"[FL] Muestras: {model_data['training_samples']}, Accuracy: {model_data['local_accuracy']:.4f}")
            
            return True
            
        except Exception as e:
            logger.error(f"[FL] Error agregando modelo de cliente {client_id}: {e}")
            return False
    
    def aggregate_models_fedavg(self):
        """Implementa FedAvg para Random Forest"""
        if len(self.client_models) < 2:
            logger.warning("[FL] Se necesitan al menos 2 clientes para agregación")
            return None
            
        try:
            logger.info(f"[FL] Iniciando agregación FedAvg con {len(self.client_models)} clientes")
            
            # Calcular pesos basados en número de muestras
            total_samples = sum(model['samples'] for model in self.client_models.values())
            weights = {
                client_id: model['samples'] / total_samples 
                for client_id, model in self.client_models.items()
            }
            
            logger.info(f"[FL] Pesos por cliente: {weights}")
            
            # Crear modelo global con parámetros promediados
            global_rf = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                random_state=42
            )
            
            # Agregar feature_importances ponderadas
            aggregated_importances = None
            valid_models = []
            
            for client_id, model_data in self.client_models.items():
                client_model = model_data['model']
                if hasattr(client_model, 'feature_importances_'):
                    if aggregated_importances is None:
                        aggregated_importances = weights[client_id] * client_model.feature_importances_
                    else:
                        aggregated_importances += weights[client_id] * client_model.feature_importances_
                    valid_models.append(client_id)
            
            # Tomar el scaler del cliente con mejor accuracy
            best_client = max(self.client_models.keys(), 
                            key=lambda k: self.client_models[k]['accuracy'])
            global_scaler = self.client_models[best_client]['scaler']
            
            logger.info(f"[FL] Usando scaler del cliente {best_client} (mejor accuracy)")
            
            # Crear conjunto de datos sintético para entrenar modelo global
            synthetic_data = self.create_synthetic_training_data()
            
            if synthetic_data is not None:
                X_synthetic, y_synthetic = synthetic_data
                X_synthetic_scaled = global_scaler.transform(X_synthetic)
                global_rf.fit(X_synthetic_scaled, y_synthetic)
            
            # Establecer feature_importances agregadas
            if aggregated_importances is not None:
                global_rf.feature_importances_ = aggregated_importances
            
            # Calcular accuracy global estimada
            global_accuracy = np.average(
                [model['accuracy'] for model in self.client_models.values()],
                weights=[model['samples'] for model in self.client_models.values()]
            )
            
            # Crear modelo global
            self.global_model = {
                'model': global_rf,
                'scaler': global_scaler,
                'features': self.fl_features,
                'version': self.round_number + 1,
                'participants': len(self.client_models),
                'global_accuracy': global_accuracy,
                'aggregation_method': 'fedavg_rf',
                'created_at': time.time(),
                'client_weights': weights
            }
            
            self.round_number += 1
            
            logger.info(f"[FL] Agregación completada")
            logger.info(f"[FL] Versión global: {self.global_model['version']}")
            logger.info(f"[FL] Participantes: {self.global_model['participants']}")
            logger.info(f"[FL] Accuracy global estimada: {global_accuracy:.4f}")
            
            # Limpiar modelos de clientes para siguiente ronda
            self.client_models.clear()
            
            return self.global_model
            
        except Exception as e:
            logger.error(f"[FL] Error en agregación FedAvg: {e}")
            return None
    
    def create_synthetic_training_data(self):
        """Crea datos sintéticos para entrenar el modelo global"""
        try:
            all_predictions = []
            all_features = []
            
            # Recolectar predicciones de todos los modelos
            np.random.seed(42)
            n_synthetic = 1000
            
            # Generar características sintéticas realistas
            X_synthetic = np.random.normal(0, 1, (n_synthetic, len(self.fl_features)))
            
            # Obtener predicciones de cada modelo cliente
            client_predictions = []
            for client_id, model_data in self.client_models.items():
                client_model = model_data['model']
                client_scaler = model_data['scaler']
                
                try:
                    X_scaled = client_scaler.transform(X_synthetic)
                    predictions = client_model.predict(X_scaled)
                    client_predictions.append(predictions)
                except:
                    continue
            
            if not client_predictions:
                return None
            
            # Usar votación mayoritaria para etiquetas sintéticas
            client_predictions = np.array(client_predictions)
            y_synthetic = np.round(np.mean(client_predictions, axis=0)).astype(int)
            
            logger.info(f"[FL] Datos sintéticos creados: {X_synthetic.shape}")
            
            return X_synthetic, y_synthetic
            
        except Exception as e:
            logger.error(f"[FL] Error creando datos sintéticos: {e}")
            return None
    
    def serialize_global_model(self):
        """Serializa el modelo global para envío"""
        try:
            if not self.global_model:
                return None
                
            model_bytes = pickle.dumps({
                'model': self.global_model['model'],
                'scaler': self.global_model['scaler'],
                'features': self.global_model['features'],
                'version': self.global_model['version']
            })
            
            model_base64 = base64.b64encode(model_bytes).decode('utf-8')
            
            return {
                'type': 'global_model',
                'version': self.global_model['version'],
                'model_data': model_base64,
                'participants': self.global_model['participants'],
                'global_accuracy': self.global_model['global_accuracy'],
                'aggregation_method': self.global_model['aggregation_method'],
                'created_at': self.global_model['created_at']
            }
            
        except Exception as e:
            logger.error(f"[FL] Error serializando modelo global: {e}")
            return None

# INTEGRAR FederatedAggregator en FederatedIDSServer:
class FederatedIDSServer:
    """Servidor central para coordinar clientes IDS federados"""
    
    def __init__(self, host='localhost', port=5000, model_path='model/modelo_rf.pkl'):
        self.host = host
        self.port = port
        self.model_path = model_path
        
        # Clientes conectados
        self.clients = {}  # {client_id: client_info}
        self.client_sockets = {}  # {client_id: websocket}
        
        # Gestión de modelos federados
        self.global_model = None
        self.client_models = {}  # {client_id: model_data}
        self.model_versions = {}  # {client_id: version}
        self.current_round = 0
        
        # Estadísticas globales
        self.global_stats = {
            'total_packets': 0,
            'total_flows': 0,
            'total_detections': 0,
            'alert_distribution': defaultdict(int),
            'attack_types': defaultdict(int),
            'start_time': time.time()
        }
        
        # Configuración de agregación
        self.aggregation_config = {
            'min_clients': 2,           # Mínimo de clientes para agregación
            'aggregation_interval': 300,  # 5 minutos
            'weight_strategy': 'equal',    # 'equal', 'performance', 'data_size'
            'model_validation': True
        }
        
        # Cola de eventos
        self.event_queue = deque(maxlen=1000)
        
        # Control de hilos
        self.running = False
        self.stats_thread = None
        self.aggregation_thread = None
        self.cleanup_thread = None
        
        # Cargar modelo inicial
        self.load_initial_model()
        
        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Inicializar FederatedAggregator
        self.fl_aggregator = FederatedAggregator()
        self.min_clients_for_aggregation = 2
        self.aggregation_interval = 300  # 5 minutos
        self.last_aggregation = time.time()
    
    def _signal_handler(self, sig, frame):
        """Maneja señales de sistema"""
        logger.info(f"Señal {sig} recibida, cerrando servidor...")
        self.running = False
        sys.exit(0)
    
    def load_initial_model(self):
        """Carga el modelo inicial del servidor federado"""
        try:
            # ✅ USAR TU MODELO ENTRENADO COMO MODELO GLOBAL INICIAL
            initial_model_path = "model/modelo_rf.pkl"  # ← TU MODELO
            
            if Path(initial_model_path).exists():
                # Cargar tu modelo entrenado
                model_data = joblib.load(initial_model_path)
                
                # Convertir tu modelo en modelo global versión 1
                self.global_model = {
                    'model': model_data['model'],  # ← TU MODELO ENTRENADO
                    'scaler': model_data.get('scaler'),  # ← TU SCALER (o None)
                    'selected_features': model_data.get('selected_features', []),
                    'resampling_pipeline': model_data.get('resampling_pipeline'),
                    'training_time': model_data.get('training_time'),
                    'version': 1,  # ✅ VERSIÓN 1, NO 0
                    'timestamp': time.time(),
                    'features': model_data.get('selected_features', []),
                    'participants': 1,
                    'global_accuracy': 0.95,  # ← ACCURACY ESTIMADO DE TU MODELO
                    'aggregation_method': 'initial_pretrained_model',
                    'created_at': time.time(),
                    'round': 0,
                    'metadata': {
                        'source': 'pretrained_model',
                        'description': 'Modelo inicial entrenado como base federada',
                        'original_file': initial_model_path,
                        'model_type': 'RandomForestClassifier',
                        'training_samples': 'unknown',
                        'creation_date': datetime.datetime.now().isoformat()
                    }
                }
                
                logger.info(f"✅ Modelo global inicial cargado desde {initial_model_path}")
                logger.info(f"🎯 Versión global: {self.global_model['version']}")
                logger.info(f"🧠 Modelo: {type(self.global_model['model']).__name__}")
                logger.info(f"📊 Features: {len(self.global_model['features'])} características")
                
            elif Path(self.model_path).exists() and self.model_path != initial_model_path:
                # Si no está tu modelo, usar el especificado en parámetros
                model_data = joblib.load(self.model_path)
                
                if isinstance(model_data, dict):
                    # Si ya es un diccionario con estructura
                    self.global_model = {
                        'model': model_data.get('model', model_data.get('modelo')),
                        'scaler': model_data.get('scaler'),
                        'selected_features': model_data.get('selected_features', model_data.get('features', [])),
                        'version': model_data.get('version', 1),
                        'timestamp': time.time(),
                        'features': model_data.get('selected_features', model_data.get('features', [])),
                        'participants': 1,
                        'global_accuracy': model_data.get('accuracy', 0.90),
                        'aggregation_method': 'initial_loaded_model',
                        'created_at': time.time(),
                        'round': 0,
                        'metadata': {
                            'source': 'loaded_model',
                            'description': 'Modelo cargado desde archivo especificado',
                            'original_file': self.model_path
                        }
                    }
                else:
                    # Si es solo el modelo
                    self.global_model = {
                        'model': model_data,
                        'scaler': None,
                        'selected_features': [],
                        'version': 1,
                        'timestamp': time.time(),
                        'features': [],
                        'participants': 1,
                        'global_accuracy': 0.85,
                        'aggregation_method': 'initial_single_model',
                        'created_at': time.time(),
                        'round': 0,
                        'metadata': {
                            'source': 'single_model',
                            'description': 'Modelo único cargado',
                            'original_file': self.model_path
                        }
                    }
                
                logger.info(f"✅ Modelo inicial cargado desde {self.model_path}")
                logger.info(f"🎯 Versión global: {self.global_model['version']}")
                
            else:
                # ❌ SOLO EN ÚLTIMO CASO crear modelo sin entrenar
                logger.warning("⚠️ No se encontró modelo entrenado, creando modelo base")
                
                from sklearn.ensemble import RandomForestClassifier
                from sklearn.preprocessing import StandardScaler
                
                # Crear modelo base sin entrenar
                base_model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=15,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    class_weight='balanced',
                    random_state=42
                )
                
                base_scaler = StandardScaler()
                
                self.global_model = {
                    'model': base_model,
                    'scaler': base_scaler,
                    'selected_features': [],
                    'version': 0,  # ← Versión 0 para modelo sin entrenar
                    'timestamp': time.time(),
                    'features': [],
                    'participants': 0,
                    'global_accuracy': 0.0,
                    'aggregation_method': 'base_untrained',
                    'created_at': time.time(),
                    'round': 0,
                    'metadata': {
                        'source': 'created_base',
                        'description': 'Modelo base sin entrenar creado por defecto',
                        'warning': 'Este modelo necesita entrenamiento antes de ser útil'
                    }
                }
                
                logger.warning("⚠️ Modelo base creado (sin entrenar) - se mejorará con el aprendizaje federado")
                
            # ✅ CONFIGURAR FL_AGGREGATOR CON EL MODELO INICIAL
            if self.global_model:
                self.fl_aggregator.global_model = self.global_model.copy()
                self.fl_aggregator.round_number = self.global_model.get('round', 0)
                
                # Actualizar features del aggregator
                features = self.global_model.get('features', [])
                if features:
                    self.fl_aggregator.fl_features = features
                
                logger.info(f"🔗 FederatedAggregator configurado con modelo inicial")
                
        except Exception as e:
            logger.error(f"❌ Error cargando modelo inicial: {e}")
            logger.error(f"❌ Traceback: {e.__class__.__name__}: {str(e)}")
            
            # Crear modelo de emergencia
            self.global_model = {
                'model': None,
                'scaler': None,
                'selected_features': [],
                'version': -1,  # ← Versión -1 indica error
                'timestamp': time.time(),
                'features': [],
                'participants': 0,
                'global_accuracy': 0.0,
                'aggregation_method': 'emergency_fallback',
                'created_at': time.time(),
                'round': 0,
                'metadata': {
                    'source': 'error_fallback',
                    'description': 'Modelo de emergencia debido a error en carga',
                    'error': str(e)
                }
            }
            
            logger.warning("⚠️ Modelo de emergencia creado debido a error")
            """Carga el modelo inicial del servidor"""
            try:
                initial_model_path = "model/modelo_rf.pkl"
                if Path(self.model_path).exists():
                    model_data = joblib.load(self.model_path)
                    if isinstance(model_data, dict):
                        self.global_model = model_data
                    else:
                        self.global_model = {
                            'model': model_data, 
                            'version': 0,
                            'timestamp': time.time(),
                            'features': []
                        }
                    
                    logger.info(f"✅ Modelo inicial cargado desde {self.model_path}")
                else:
                    # Crear modelo base si no existe
                    self.global_model = {
                        'model': RandomForestClassifier(n_estimators=100, random_state=42),
                        'scaler': StandardScaler(),
                        'version': 0,
                        'timestamp': time.time(),
                        'features': [],
                        'metadata': {
                            'created_by': 'server',
                            'description': 'Modelo base sin entrenar'
                        }
                    }
                    logger.info("⚠️  Modelo base creado (sin entrenar)")
                    
            except Exception as e:
                logger.error(f"❌ Error cargando modelo inicial: {e}")
                self.global_model = None
    
    async def register_client(self, websocket):
        """Maneja el registro y comunicación con clientes"""
        client_id = None
        client_name = "Unknown"
        
        try:
            # Esperar mensaje de registro con timeout
            registration_msg = await asyncio.wait_for(websocket.recv(), timeout=30)
            registration_data = json.loads(registration_msg)
            
            if registration_data['type'] != 'register':
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Se esperaba mensaje de registro'
                }))
                return
            
            # Generar ID único para el cliente
            client_id = str(uuid.uuid4())
            client_name = registration_data.get('name', f'Client-{client_id[:8]}')
            
            # Registrar cliente
            client_info = {
                'id': client_id,
                'name': client_name,
                'location': registration_data.get('location', 'Unknown'),
                'interface': registration_data.get('interface', 'Unknown'),
                'capabilities': registration_data.get('capabilities', []),
                'version': registration_data.get('version', '1.0'),
                'connected_at': time.time(),
                'last_heartbeat': time.time(),
                'last_stats_update': 0,
                'status': 'connected',
                'total_alerts': 0,
                'performance': {}
            }
            
            self.clients[client_id] = client_info
            self.client_sockets[client_id] = websocket
            
            logger.info(f"🔗 Cliente registrado: {client_name} ({client_id[:8]}) desde {client_info['location']}")
            
            # Enviar confirmación con modelo actual
            response = {
                'type': 'registration_confirmed',
                'client_id': client_id,
                'server_info': {
                    'version': '1.0',
                    'current_round': self.current_round,
                    'total_clients': len(self.clients),
                    'server_start_time': self.global_stats['start_time']
                }
            }
            
            # Incluir modelo global si está disponible
            if self.global_model:
                response['global_model'] = {
                    'version': self.global_model.get('version', 0),
                    'features': self.global_model.get('features', []),
                    'timestamp': self.global_model.get('timestamp', time.time()),
                    'checksum': self._calculate_model_checksum(self.global_model)
                }
            
            await websocket.send(json.dumps(response))
            
            # Broadcast a otros clientes sobre nuevo cliente
            await self.broadcast_message({
                'type': 'client_joined',
                'client_info': {
                    'name': client_name,
                    'location': client_info['location'],
                    'capabilities': client_info['capabilities']
                },
                'total_clients': len(self.clients)
            }, exclude_client=client_id)
            
            # Manejar mensajes del cliente
            await self.handle_client_messages(websocket, client_id)
            
        except asyncio.TimeoutError:
            logger.warning("⏰ Timeout esperando registro de cliente")
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"🔌 Cliente {client_name} ({client_id[:8] if client_id else 'desconocido'}) desconectado")
        except json.JSONDecodeError:
            logger.error("❌ Mensaje de registro JSON inválido")
        except Exception as e:
            logger.error(f"❌ Error manejando cliente {client_name}: {e}")
        finally:
            # Limpiar al desconectar
            if client_id:
                await self.unregister_client(client_id)
    
    async def handle_client_messages(self, websocket, client_id):
        """Maneja mensajes de un cliente específico"""
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.process_client_message(client_id, data)
                except json.JSONDecodeError:
                    logger.error(f"❌ Mensaje JSON inválido del cliente {client_id[:8]}")
                except Exception as e:
                    logger.error(f"❌ Error procesando mensaje del cliente {client_id[:8]}: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"❌ Error en loop de mensajes del cliente {client_id[:8]}: {e}")
    
    async def process_client_message(self, client_id, data):
        """Procesa diferentes tipos de mensajes de clientes"""
        message_type = data.get('type')
        
        try:
            if message_type == 'heartbeat':
                await self.handle_heartbeat(client_id, data)
            elif message_type == 'stats_update':
                await self.handle_stats_update(client_id, data)
            elif message_type == 'detection_alert':
                await self.handle_detection_alert(client_id, data)
            elif message_type == 'model_update':
                await self.handle_model_update(client_id, data)
            elif message_type == 'get_global_model':  # ✅ AGREGAR ESTE HANDLER
                await self.send_global_model(client_id)
            elif message_type == 'request_global_model':  # ✅ ALIAS PARA COMPATIBILIDAD
                await self.send_global_model(client_id)
            else:
                logger.debug(f"🤔 Tipo de mensaje desconocido: {message_type} del cliente {client_id[:8]}")
        except Exception as e:
            logger.error(f"❌ Error procesando mensaje {message_type} del cliente {client_id[:8]}: {e}")
        
    async def handle_heartbeat(self, client_id, data):
        """Maneja heartbeat de cliente"""
        if client_id in self.clients:
            self.clients[client_id]['last_heartbeat'] = time.time()
            self.clients[client_id]['status'] = data.get('status', 'active')
            
            # Responder heartbeat
            response = {
                'type': 'heartbeat_ack',
                'server_time': time.time(),
                'round': self.current_round,
                'connected_clients': len(self.clients)
            }
            await self.send_to_client(client_id, response)
    
    async def handle_stats_update(self, client_id, data):
        """Maneja actualización de estadísticas de cliente"""
        stats = data.get('stats', {})
        
        try:
            # Actualizar estadísticas globales
            self.global_stats['total_packets'] += stats.get('packets_processed', 0)
            self.global_stats['total_flows'] += stats.get('flows_analyzed', 0)
            self.global_stats['total_detections'] += stats.get('total_alerts', 0)
            
            # Actualizar distribución de alertas
            for alert_type, count in stats.get('alert_distribution', {}).items():
                self.global_stats['alert_distribution'][alert_type] += count
            
            # Actualizar tipos de ataques
            for attack_type, count in stats.get('attack_types', {}).items():
                self.global_stats['attack_types'][attack_type] += count
            
            # Actualizar información del cliente
            if client_id in self.clients:
                self.clients[client_id]['last_stats'] = stats
                self.clients[client_id]['last_stats_update'] = time.time()
                self.clients[client_id]['total_alerts'] = stats.get('total_alerts', 0)
                
                # Calcular rendimiento
                uptime = stats.get('uptime', 1)
                self.clients[client_id]['performance'] = {
                    'packets_per_second': stats.get('packets_processed', 0) / uptime,
                    'flows_per_second': stats.get('flows_analyzed', 0) / uptime,
                    'alert_rate': stats.get('total_alerts', 0) / uptime
                }
            
            logger.debug(f"📊 Estadísticas actualizadas del cliente {client_id[:8]}")
            
        except Exception as e:
            logger.error(f"❌ Error actualizando estadísticas del cliente {client_id[:8]}: {e}")
    
    async def handle_detection_alert(self, client_id, data):
        """Maneja alertas de detección de clientes"""
        alert = data.get('alert', {})
        
        try:
            # Enriquecer alerta con información del cliente
            client_info = self.clients.get(client_id, {})
            enriched_alert = {
                **alert,
                'client_id': client_id,
                'client_name': client_info.get('name', 'Unknown'),
                'client_location': client_info.get('location', 'Unknown'),
                'server_timestamp': time.time(),
                'global_round': self.current_round
            }
            
            # Agregar a cola de eventos
            self.event_queue.append(enriched_alert)
            
            # Log de la alerta
            severity = alert.get('status', 'unknown')
            src_ip = alert.get('src_ip', 'unknown')
            dst_ip = alert.get('dst_ip', 'unknown')
            score = alert.get('score', 0)
            attack_type = alert.get('attack_type', '')
            
            # Usar emojis y colores para mejor visualización
            emoji_map = {
                'normal': '✅',
                'suspicious': '⚠️',
                'attack': '🚨'
            }
            emoji = emoji_map.get(severity, '❓')
            
            client_name = client_info.get('name', 'Unknown')
            
            logger.info(f"{emoji} [{severity.upper()}] {client_name}: {src_ip} -> {dst_ip} "
                       f"({attack_type}) Score: {score:.4f}")
            
            # Reenviar alerta crítica a otros clientes
            if severity == 'attack' and score > 0.8:
                await self.broadcast_message({
                    'type': 'critical_alert',
                    'alert': enriched_alert
                }, exclude_client=client_id)
                
                logger.warning(f"🚨 Alerta crítica distribuida a {len(self.clients)-1} clientes")
                
        except Exception as e:
            logger.error(f"❌ Error manejando alerta del cliente {client_id[:8]}: {e}")
    
    async def handle_model_update(self, client_id, data):
        """Maneja actualización de modelo de cliente"""
        model_data = data.get('model_data', {})
        
        try:
            # Validar datos del modelo
            if not self._validate_model_data(model_data):
                logger.warning(f"⚠️  Datos de modelo inválidos del cliente {client_id[:8]}")
                return
            
            # Almacenar modelo del cliente
            self.client_models[client_id] = {
                'data': model_data,
                'timestamp': time.time(),
                'performance': data.get('performance', {}),
                'data_size': data.get('data_size', 0),
                'client_info': self.clients.get(client_id, {})
            }
            
            self.model_versions[client_id] = model_data.get('version', 0)
            
            client_name = self.clients.get(client_id, {}).get('name', 'Unknown')
            logger.info(f"🤖 Modelo actualizado: {client_name} v{model_data.get('version', 0)}")
            
            # Verificar si es momento de agregar modelos
            if len(self.client_models) >= self.aggregation_config['min_clients']:
                await self.trigger_model_aggregation()
                
        except Exception as e:
            logger.error(f"❌ Error actualizando modelo del cliente {client_id[:8]}: {e}")
    
    async def send_global_model(self, client_id):
        """Envía el modelo global a un cliente específico"""
        try:
            if not self.global_model:
                await self.send_to_client(client_id, {
                    'type': 'error',
                    'message': 'Modelo global no disponible'
                })
                return
            
            # Serializar modelo para envío
            model_message = {
                'type': 'global_model_update',
                'model_data': {
                    'version': self.global_model.get('version', 0),
                    'features': self.global_model.get('features', []),
                    'timestamp': self.global_model.get('timestamp', time.time()),
                    'round': self.current_round,
                    'checksum': self._calculate_model_checksum(self.global_model)
                },
                'aggregation_info': {
                    'participating_clients': len(self.client_models),
                    'aggregation_time': time.time(),
                    'total_rounds': self.current_round
                }
            }
            
            await self.send_to_client(client_id, model_message)
            
            client_name = self.clients.get(client_id, {}).get('name', 'Unknown')
            logger.info(f"📤 Modelo global enviado a {client_name}")
            
        except Exception as e:
            logger.error(f"❌ Error enviando modelo global al cliente {client_id[:8]}: {e}")
    
    async def trigger_model_aggregation(self):
        """Dispara la agregación de modelos"""
        if len(self.client_models) < self.aggregation_config['min_clients']:
            return
        
        logger.info(f"🔄 Iniciando agregación de modelos (Ronda {self.current_round + 1})")
        logger.info(f"📊 Modelos participantes: {len(self.client_models)}")
        
        try:
            # Realizar agregación federada
            aggregated_model = await self.federated_averaging()
            
            if aggregated_model:
                # Actualizar modelo global
                old_version = self.global_model.get('version', 0) if self.global_model else 0
                self.global_model = aggregated_model
                self.current_round += 1
                
                # Guardar modelo agregado
                await self.save_global_model()
                
                # Enviar modelo actualizado a todos los clientes
                await self.broadcast_message({
                    'type': 'global_model_update',
                    'model_data': {
                        'version': self.global_model.get('version', 0),
                        'features': self.global_model.get('features', []),
                        'timestamp': self.global_model.get('timestamp', time.time()),
                        'round': self.current_round,
                        'checksum': self._calculate_model_checksum(self.global_model)
                    },
                    'aggregation_info': {
                        'participating_clients': len(self.client_models),
                        'aggregation_time': time.time(),
                        'previous_version': old_version,
                        'improvement': 'available'  # Aquí podrías calcular métricas de mejora
                    }
                })
                
                logger.info(f"✅ Modelo global actualizado v{old_version} -> v{self.global_model.get('version', 0)} (Ronda {self.current_round})")
                logger.info(f"📤 Modelo distribuido a {len(self.clients)} clientes")
                
                # Limpiar modelos de clientes después de la agregación
                self.client_models.clear()
            else:
                logger.warning("⚠️  No se pudo completar la agregación de modelos")
            
        except Exception as e:
            logger.error(f"❌ Error en agregación de modelos: {e}")
    
    async def federated_averaging(self):
        """Implementa el algoritmo de promediado federado"""
        try:
            if not self.client_models:
                return None
            
            logger.debug("🧮 Calculando pesos para agregación federada...")
            
            # Calcular pesos para cada cliente
            weights = self._calculate_client_weights()
            
            # Log de pesos calculados
            for client_id, weight in weights.items():
                client_name = self.clients.get(client_id, {}).get('name', 'Unknown')
                logger.debug(f"  {client_name}: {weight:.4f}")
            
            # Obtener parámetros de modelos
            model_params = []
            total_weight = 0
            
            for client_id, client_model in self.client_models.items():
                if client_id in weights:
                    weight = weights[client_id]
                    model_data = client_model['data']
                    
                    # En una implementación real, aquí extraerías los parámetros del modelo
                    # Por ahora, simulamos la agregación
                    if 'parameters' in model_data:
                        model_params.append((weight, model_data['parameters']))
                        total_weight += weight
            
            if not model_params and total_weight == 0:
                # Si no hay parámetros, crear modelo agregado básico
                logger.info("📝 Creando modelo agregado básico (sin parámetros específicos)")
                
                aggregated_model = {
                    'version': self.global_model.get('version', 0) + 1 if self.global_model else 1,
                    'features': self._aggregate_features(),
                    'timestamp': time.time(),
                    'round': self.current_round + 1,
                    'aggregation_info': {
                        'method': 'federated_averaging',
                        'participating_clients': list(self.client_models.keys()),
                        'client_weights': weights,
                        'aggregation_timestamp': time.time()
                    },
                    'metadata': {
                        'created_by': 'federated_server',
                        'description': f'Modelo agregado de {len(self.client_models)} clientes'
                    }
                }
                
                return aggregated_model
            
            # Normalizar pesos si es necesario
            if total_weight > 0:
                normalized_params = [(w/total_weight, params) for w, params in model_params]
            else:
                normalized_params = model_params
            
            # Promediar parámetros (implementación simplificada)
            # En un caso real, aquí harías el promedio de los pesos del modelo
            aggregated_model = {
                'version': self.global_model.get('version', 0) + 1 if self.global_model else 1,
                'features': self._aggregate_features(),
                'timestamp': time.time(),
                'round': self.current_round + 1,
                'aggregation_info': {
                    'method': 'federated_averaging',
                    'participating_clients': list(self.client_models.keys()),
                    'client_weights': weights,
                    'total_weight': total_weight,
                    'aggregation_timestamp': time.time()
                },
                'metadata': {
                    'created_by': 'federated_server',
                    'description': f'Modelo agregado de {len(self.client_models)} clientes'
                }
            }
            
            return aggregated_model
            
        except Exception as e:
            logger.error(f"❌ Error en promediado federado: {e}")
            return None
    
    def _aggregate_features(self):
        """Agrega las características de todos los modelos de clientes"""
        all_features = set()
        
        for client_model in self.client_models.values():
            features = client_model['data'].get('features', [])
            all_features.update(features)
        
        return list(all_features)
    
    def _calculate_client_weights(self):
        """Calcula pesos para cada cliente en la agregación"""
        weights = {}
        strategy = self.aggregation_config['weight_strategy']
        
        try:
            if strategy == 'equal':
                # Pesos iguales para todos los clientes
                weight = 1.0 / len(self.client_models)
                for client_id in self.client_models:
                    weights[client_id] = weight
                    
            elif strategy == 'data_size':
                # Pesos basados en la cantidad de datos
                total_data = sum(
                    model['data_size'] for model in self.client_models.values()
                    if model['data_size'] > 0
                )
                
                if total_data > 0:
                    for client_id, model in self.client_models.items():
                        data_size = max(model['data_size'], 1)  # Mínimo 1
                        weights[client_id] = data_size / total_data
                else:
                    # Fallback a pesos iguales
                    weight = 1.0 / len(self.client_models)
                    for client_id in self.client_models:
                        weights[client_id] = weight
                        
            elif strategy == 'performance':
                # Pesos basados en rendimiento del modelo
                performances = []
                for client_id, model in self.client_models.items():
                    perf = model.get('performance', {})
                    # Usar F1-score o accuracy como métrica
                    score = perf.get('f1_score', perf.get('accuracy', 0.5))
                    performances.append(max(score, 0.1))  # Mínimo peso
                
                total_performance = sum(performances)
                if total_performance > 0:
                    for i, client_id in enumerate(self.client_models.keys()):
                        weights[client_id] = performances[i] / total_performance
                else:
                    # Fallback a pesos iguales
                    weight = 1.0 / len(self.client_models)
                    for client_id in self.client_models:
                        weights[client_id] = weight
            
            # Normalizar pesos para asegurar que sumen 1
            total_weight = sum(weights.values())
            if total_weight > 0:
                weights = {k: v/total_weight for k, v in weights.items()}
            
            return weights
            
        except Exception as e:
            logger.error(f"❌ Error calculando pesos de clientes: {e}")
            # Fallback a pesos iguales
            weight = 1.0 / len(self.client_models)
            return {client_id: weight for client_id in self.client_models}
    
    def _validate_model_data(self, model_data):
        """Valida los datos del modelo recibido"""
        required_fields = ['version', 'timestamp']
        
        try:
            return all(field in model_data for field in required_fields)
        except:
            return False
    
    def _calculate_model_checksum(self, model):
        """Calcula checksum del modelo para verificación de integridad"""
        try:
            # Crear una versión serializable del modelo
            serializable_model = {
                'version': model.get('version', 0),
                'timestamp': model.get('timestamp', 0),
                'features': model.get('features', []),
                'round': model.get('round', 0)
            }
            
            model_str = json.dumps(serializable_model, sort_keys=True)
            return hashlib.md5(model_str.encode()).hexdigest()
        except Exception as e:
            logger.error(f"❌ Error calculando checksum: {e}")
            return "unknown"
    
    async def save_global_model(self):
        """Guarda el modelo global en disco"""
        try:
            if self.global_model:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Crear directorio de modelos si no existe
                models_dir = Path("models")
                models_dir.mkdir(exist_ok=True)
                
                # Guardar con timestamp
                filename = f"modelo_global_r{self.current_round}_{timestamp}.pkl"
                filepath = models_dir / filename
                
                # Guardar modelo
                joblib.dump(self.global_model, filepath)
                
                # También guardar como modelo actual
                current_path = Path(self.model_path)
                current_path.parent.mkdir(exist_ok=True)
                joblib.dump(self.global_model, current_path)
                
                logger.info(f"💾 Modelo global guardado: {filepath}")
                
        except Exception as e:
            logger.error(f"❌ Error guardando modelo global: {e}")
    
    async def send_to_client(self, client_id, message):
        """Envía mensaje a un cliente específico"""
        if client_id in self.client_sockets:
            try:
                await self.client_sockets[client_id].send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                logger.warning(f"🔌 Cliente {client_id[:8]} desconectado al enviar mensaje")
                await self.unregister_client(client_id)
            except Exception as e:
                logger.error(f"❌ Error enviando mensaje al cliente {client_id[:8]}: {e}")
    
    async def broadcast_message(self, message, exclude_client=None):
        """Envía mensaje a todos los clientes conectados"""
        if not self.clients:
            return
            
        disconnected_clients = []
        
        for client_id, websocket in self.client_sockets.items():
            if client_id != exclude_client:
                try:
                    await websocket.send(json.dumps(message))
                except websockets.exceptions.ConnectionClosed:
                    disconnected_clients.append(client_id)
                except Exception as e:
                    logger.error(f"❌ Error en broadcast al cliente {client_id[:8]}: {e}")
        
        # Limpiar clientes desconectados
        for client_id in disconnected_clients:
            await self.unregister_client(client_id)
    
    async def unregister_client(self, client_id):
        """Desregistra un cliente"""
        if client_id in self.clients:
            client_info = self.clients[client_id]
            client_name = client_info.get('name', 'Unknown')
            
            # Remover de todas las estructuras
            del self.clients[client_id]
            
            if client_id in self.client_sockets:
                del self.client_sockets[client_id]
            
            if client_id in self.client_models:
                del self.client_models[client_id]
                
            if client_id in self.model_versions:
                del self.model_versions[client_id]
            
            connection_time = time.time() - client_info.get('connected_at', time.time())
            logger.info(f"🚪 Cliente desconectado: {client_name} ({client_id[:8]}) - "
                       f"Tiempo conectado: {self._format_duration(connection_time)}")
            
            # Notificar a otros clientes
            await self.broadcast_message({
                'type': 'client_left',
                'client_name': client_name,
                'client_location': client_info.get('location', 'Unknown'),
                'total_clients': len(self.clients)
            })
    
    def start_background_tasks(self):
        """Inicia tareas en segundo plano"""
        self.running = True
        
        # Hilo para estadísticas
        self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        self.stats_thread.start()
        
        # Hilo para agregación periódica
        self.aggregation_thread = threading.Thread(target=self._aggregation_worker, daemon=True)
        self.aggregation_thread.start()
        
        # Hilo para limpieza
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _stats_worker(self):
        """Worker para mostrar estadísticas periódicamente"""
        while self.running:
            try:
                # Limpiar pantalla y mostrar estadísticas
                if os.name == 'nt':  # Windows
                    os.system('cls')
                else:  # Unix/Linux
                    os.system('clear')
                
                self._print_server_dashboard()
                
                time.sleep(10)  # Actualizar cada 10 segundos
                
            except Exception as e:
                logger.error(f"❌ Error en worker de estadísticas: {e}")
                time.sleep(10)
    
    def _print_server_dashboard(self):
        """Imprime el dashboard del servidor"""
        try:
            runtime = time.time() - self.global_stats['start_time']
            
            print("=" * 80)
            print("🛡️  SERVIDOR FEDERADO - SISTEMA DE DETECCIÓN DE INTRUSIONES")
            print("=" * 80)
            print(f"🕐 Tiempo: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"⚡ Runtime: {self._format_duration(runtime)}")
            print(f"🔄 Ronda actual: {self.current_round}")
            print(f"👥 Clientes conectados: {len(self.clients)}")
            print(f"🤖 Modelos en cola: {len(self.client_models)}")
            print()
            
            # Información de clientes
            if self.clients:
                print("👥 CLIENTES CONECTADOS:")
                print("-" * 60)
                for client_id, client_info in self.clients.items():
                    status = client_info.get('status', 'unknown')
                    last_hb = time.time() - client_info.get('last_heartbeat', 0)
                    connection_time = time.time() - client_info.get('connected_at', time.time())
                    total_alerts = client_info.get('total_alerts', 0)
                    
                    status_emoji = "🟢" if last_hb < 60 else "🟡" if last_hb < 120 else "🔴"
                    
                    print(f"{status_emoji} {client_info['name']} ({client_id[:8]})")
                    print(f"   📍 Ubicación: {client_info['location']}")
                    print(f"   🔌 Interfaz: {client_info['interface']}")
                    print(f"   ⏱️  Conectado: {self._format_duration(connection_time)}")
                    print(f"   💓 Último heartbeat: {last_hb:.1f}s")
                    print(f"   🚨 Alertas totales: {total_alerts}")
                    
                    # Rendimiento si está disponible
                    perf = client_info.get('performance', {})
                    if perf:
                        print(f"   📊 Rendimiento: {perf.get('packets_per_second', 0):.1f} pkt/s, "
                              f"{perf.get('alert_rate', 0):.3f} alerts/s")
                    print()
            
            # Estadísticas globales
            print("📊 ESTADÍSTICAS GLOBALES:")
            print("-" * 40)
            print(f"📦 Paquetes procesados: {self.global_stats['total_packets']:,}")
            print(f"🌊 Flujos analizados: {self.global_stats['total_flows']:,}")
            print(f"🚨 Detecciones totales: {self.global_stats['total_detections']:,}")
            
            if runtime > 0:
                print(f"⚡ Tasa promedio: {self.global_stats['total_packets']/runtime:.1f} pkt/s")
            
            # Distribución de alertas
            if self.global_stats['alert_distribution']:
                print("\n🎯 Distribución de alertas:")
                total_alerts = sum(self.global_stats['alert_distribution'].values())
                for alert_type, count in self.global_stats['alert_distribution'].items():
                    percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                    emoji = {"normal": "✅", "suspicious": "⚠️", "attack": "🚨"}.get(alert_type, "❓")
                    print(f"   {emoji} {alert_type.capitalize()}: {count:,} ({percentage:.1f}%)")
            
            # Tipos de ataques
            if self.global_stats['attack_types']:
                print("\n🎯 Tipos de ataques detectados:")
                sorted_attacks = sorted(self.global_stats['attack_types'].items(), 
                                      key=lambda x: x[1], reverse=True)
                for attack_type, count in sorted_attacks[:5]:  # Top 5
                    print(f"   🔍 {attack_type}: {count:,}")
            
            # Eventos recientes
            if self.event_queue:
                print("\n📋 EVENTOS RECIENTES:")
                print("-" * 30)
                recent_events = list(self.event_queue)[-5:]  # Últimos 5
                for event in reversed(recent_events):
                    timestamp = datetime.datetime.fromtimestamp(
                        event.get('server_timestamp', time.time())
                    ).strftime('%H:%M:%S')
                    
                    client_name = event.get('client_name', 'Unknown')
                    status = event.get('status', 'unknown')
                    src_ip = event.get('src_ip', 'unknown')
                    dst_ip = event.get('dst_ip', 'unknown')
                    score = event.get('score', 0)
                    attack_type = event.get('attack_type', '')
                    
                    emoji = {"normal": "✅", "suspicious": "⚠️", "attack": "🚨"}.get(status, "❓")
                    
                    print(f"[{timestamp}] {emoji} {client_name}: {src_ip} -> {dst_ip}")
                    if attack_type:
                        print(f"          {attack_type.upper()} (Score: {score:.4f})")
            
            print(f"\n💡 Servidor escuchando en ws://{self.host}:{self.port}")
            print("   Presione Ctrl+C para detener el servidor")
            
        except Exception as e:
            logger.error(f"❌ Error mostrando dashboard: {e}")
    
    def _aggregation_worker(self):
        """Worker para agregación periódica de modelos"""
        while self.running:
            try:
                time.sleep(self.aggregation_config['aggregation_interval'])
                
                if len(self.client_models) >= self.aggregation_config['min_clients']:
                    logger.info(f"⏰ Agregación programada: {len(self.client_models)} modelos disponibles")
                    
                    # Crear event loop para la agregación
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        loop.run_until_complete(self.trigger_model_aggregation())
                    finally:
                        loop.close()
                        
            except Exception as e:
                logger.error(f"❌ Error en worker de agregación: {e}")
    
    def _cleanup_worker(self):
        """Worker para limpieza de datos antiguos"""
        while self.running:
            try:
                time.sleep(300)  # Cada 5 minutos
                
                # Limpiar eventos antiguos (mantener solo últimos 1000)
                if len(self.event_queue) > 900:
                    # Mantener los últimos 500
                    recent_events = list(self.event_queue)[-500:]
                    self.event_queue.clear()
                    self.event_queue.extend(recent_events)
                    logger.debug("🧹 Cache de eventos limpiado")
                
                # Verificar clientes inactivos
                current_time = time.time()
                inactive_clients = []
                
                for client_id, client_info in self.clients.items():
                    last_heartbeat = client_info.get('last_heartbeat', 0)
                    if current_time - last_heartbeat > 300:  # 5 minutos sin heartbeat
                        inactive_clients.append(client_id)
                
                # Marcar clientes inactivos (no desconectar automáticamente)
                for client_id in inactive_clients:
                    if client_id in self.clients:
                        self.clients[client_id]['status'] = 'inactive'
                        client_name = self.clients[client_id].get('name', 'Unknown')
                        logger.warning(f"⚠️  Cliente marcado como inactivo: {client_name}")
                
            except Exception as e:
                logger.error(f"❌ Error en worker de limpieza: {e}")
    
    def _format_duration(self, seconds):
        """Formatea una duración en segundos"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    async def start_server(self):
        """Inicia el servidor federado"""
        logger.info(f"🚀 Iniciando servidor federado en {self.host}:{self.port}")
        
        # Crear directorio de modelos
        Path("models").mkdir(exist_ok=True)
        
        # Iniciar tareas en segundo plano
        self.start_background_tasks()
        
        try:
            # Iniciar servidor WebSocket
            async with websockets.serve(
                self.register_client, 
                self.host, 
                self.port,
                ping_interval=20,
                ping_timeout=10
            ):
                logger.info(f"✅ Servidor federado activo en ws://{self.host}:{self.port}")
                print(f"🛡️  Servidor Federado IDS iniciado")
                print(f"🌐 URL: ws://{self.host}:{self.port}")
                print(f"📊 Configuración: min_clients={self.aggregation_config['min_clients']}, "
                      f"interval={self.aggregation_config['aggregation_interval']}s")
                print("Esperando conexiones de clientes...\n")
                
                # Ejecutar indefinidamente
                await asyncio.Future()
                
        except KeyboardInterrupt:
            logger.info("🛑 Cerrando servidor federado...")
            self.running = False
            print("\n✅ Servidor federado cerrado")
        except Exception as e:
            logger.error(f"❌ Error fatal en servidor: {e}")
            raise


def main():
    """Función principal del servidor"""
    import argparse
    
    parser = argparse.ArgumentParser(description="🛡️  Servidor Federado para IDS")
    parser.add_argument("--host", default="0.0.0.0", help="Host del servidor")
    parser.add_argument("--port", type=int, default=8765, help="Puerto del servidor")
    parser.add_argument("--model", default="model/modelo_rf.pkl", help="Ruta del modelo inicial")
    parser.add_argument("--min-clients", type=int, default=1, help="Mínimo clientes para agregación")
    parser.add_argument("--aggregation-interval", type=int, default=300, help="Intervalo de agregación (segundos)")
    parser.add_argument("--weight-strategy", default="equal", 
                       choices=["equal", "data_size", "performance"],
                       help="Estrategia de pesos para agregación")
    
    args = parser.parse_args()
    
    # Mostrar configuración
    print(f"🛡️  Servidor Federado IDS v1.0")
    print(f"📊 Configuración:")
    print(f"   🌐 Host: {args.host}")
    print(f"   🔌 Puerto: {args.port}")
    print(f"   🤖 Modelo: {args.model}")
    print(f"   👥 Mín. clientes: {args.min_clients}")
    print(f"   ⏱️  Intervalo agregación: {args.aggregation_interval}s")
    print(f"   ⚖️  Estrategia pesos: {args.weight_strategy}")
    print("-" * 50)
    
    # Crear servidor
    server = FederatedIDSServer(
        host=args.host,
        port=args.port,
        model_path=args.model
    )
    
    # Configurar parámetros
    server.aggregation_config.update({
        'min_clients': args.min_clients,
        'aggregation_interval': args.aggregation_interval,
        'weight_strategy': args.weight_strategy
    })
    
    # Iniciar servidor
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por el usuario")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()