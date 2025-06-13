#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detector Integrado - CLIENTE FEDERADO (SIN EMOJIS)
------------------------------------------------
Cliente que usa detector.py completamente sin problemas Unicode
"""

import sys
import os
import json
import uuid
import threading
import time
import asyncio
import websockets
import pickle
import numpy as np
import psutil
from datetime import datetime
from typing import Optional, Dict, Any
import logging

# Configurar encoding para Windows ANTES de importar detector
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

# Importar el detector original COMPLETO
from detector import NetworkMonitor, CONFIG, logger

# Importar conexión BD local
try:
    from db.db import obtener_conexion
    from psycopg2.extras import RealDictCursor
    DB_AVAILABLE = True
except ImportError:
    logger.warning("BD no disponible - continuando sin BD")
    DB_AVAILABLE = False
    def obtener_conexion():
        return None

# Configurar logging sin emojis para Windows
def setup_windows_logging():
    """Configura logging compatible con Windows"""
    # Limpiar handlers existentes
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Crear handler con encoding UTF-8
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    
    # Formato simple sin emojis
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    # Configurar logger
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

class ClienteFederadoDetector(NetworkMonitor):
    """Cliente federado que hereda TODO de NetworkMonitor y añade funcionalidad BD/federada"""
    
    def __init__(self, model_path, interface='Ethernet', client_id=1, 
                 servidor_federado="ws://192.168.1.100:8765"):
        
        # Inicializar la clase padre NetworkMonitor COMPLETA
        super().__init__(model_path, interface)
        
        # Configuración del cliente federado
        self.client_id = client_id
        self.servidor_federado = servidor_federado
        
        # Estado del cliente federado
        self.connected_to_server = False
        self.server_assigned_id = None
        self.last_model_update = None
        self.rounds_participated = 0
        
        # Cola para detecciones BD
        self.detection_queue = []
        self.queue_lock = threading.Lock()
        
        # Hilos adicionales del cliente federado
        self.db_thread = None
        self.federated_thread = None
        self.stop_events = {
            'db': threading.Event(),
            'federated': threading.Event()
        }
        
        # Contadores específicos del cliente federado
        self.total_detections = 0
        self.federated_stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'model_updates_received': 0,
            'connection_attempts': 0,
            'last_heartbeat': None
        }
        
        # Configurar cliente en BD local si está disponible
        if DB_AVAILABLE:
            self.setup_client_in_db()
    
    def setup_client_in_db(self):
        """Configura este cliente en la BD local"""
        try:
            conn = obtener_conexion()
            if not conn:
                logger.warning("No se pudo conectar a BD local")
                return
            
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Crear tabla de clientes federados con estructura CORRECTA
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS federated_clients (
                        client_id INTEGER PRIMARY KEY,
                        name VARCHAR(255),
                        description TEXT,
                        ip_address VARCHAR(45),
                        port INTEGER DEFAULT 8080,
                        status VARCHAR(50) DEFAULT 'active',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        model_version VARCHAR(50),
                        total_detections INTEGER DEFAULT 0,
                        total_rounds INTEGER DEFAULT 0,
                        api_key VARCHAR(255),
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Insertar o actualizar cliente con orden CORRECTO
                cursor.execute("""
                    INSERT INTO federated_clients 
                    (client_id, name, description, ip_address, port, status, 
                     created_at, model_version, total_detections, total_rounds, 
                     api_key, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (client_id) DO UPDATE SET
                        status = 'active',
                        last_seen = CURRENT_TIMESTAMP,
                        description = EXCLUDED.description
                """, (
                    self.client_id,  # client_id PRIMERO
                    f'Cliente-Detector-{self.client_id}',
                    f'Cliente federado detector local - Servidor: {self.servidor_federado}',
                    '192.168.18.14',
                    8080,
                    'active',
                    datetime.now(),
                    'v1.0',
                    0,
                    0,
                    f'cliente_key_{self.client_id}_{int(time.time())}',
                    datetime.now()
                ))
                conn.commit()
                logger.info(f"Cliente {self.client_id} configurado en BD local")
                
        except Exception as e:
            logger.error(f"Error configurando cliente en BD: {e}")
        finally:
            if conn:
                conn.close()
    
    def start_capture(self):
        """Inicia todos los componentes del cliente federado"""
        logger.info("=== INICIANDO CLIENTE FEDERADO DETECTOR ===")
        
        # Registrar tiempo de inicio
        self.start_time = time.time()
        
        # Limpiar eventos de parada
        for event in self.stop_events.values():
            event.clear()
        
        # Iniciar hilo BD solo si está disponible
        if DB_AVAILABLE:
            self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
            self.db_thread.start()
            logger.info("[BD] Hilo BD iniciado")
        else:
            logger.warning("[BD] BD no disponible, omitiendo hilo BD")
        
        # Iniciar hilo federado
        self.federated_thread = threading.Thread(target=self._federated_worker, daemon=True)
        self.federated_thread.start()
        logger.info("[FL] Hilo federado iniciado")
        
        # Iniciar captura de red usando TODA la lógica del detector padre
        try:
            logger.info("[DETECTOR] Iniciando detector de red completo...")
            super().start_capture()  # Esto inicia TODA la lógica de detector.py
        except Exception as e:
            logger.error(f"[ERROR] Error iniciando captura: {e}")
            raise
    
    def stop_capture_threads(self):
        """Detiene todos los hilos incluyendo los del cliente federado"""
        logger.info("=== DETENIENDO CLIENTE FEDERADO ===")
        
        # Detener hilos específicos del cliente federado
        for event in self.stop_events.values():
            event.set()
        
        # Guardar detecciones pendientes en BD
        if DB_AVAILABLE:
            self._flush_detection_queue()
        
        # Detener hilos del detector padre
        super().stop_capture_threads()
        
        # Esperar hilos específicos
        if self.db_thread and self.db_thread.is_alive():
            self.db_thread.join(timeout=3.0)
        
        if self.federated_thread and self.federated_thread.is_alive():
            self.federated_thread.join(timeout=3.0)
        
        logger.info("[STOP] Cliente federado detenido completamente")
    
    def _print_detection(self, status, flow, probability, attack_type=None, pattern_scores=None):
        """
        Sobrescribe solo el método de impresión para añadir registro BD
        MANTIENE toda la lógica original del detector.py
        """
        # Llamar al método original del detector padre
        super()._print_detection(status, flow, probability, attack_type, pattern_scores)
        
        # Añadir SOLO la funcionalidad BD sin alterar la lógica de detección
        if status != 'normal' and DB_AVAILABLE:
            self.total_detections += 1
            
            # Crear registro para BD
            detection_record = {
                'detection_id': str(uuid.uuid4()),
                'client_id': self.client_id,
                'timestamp': datetime.now(),
                'source_ip': flow.src_ip,
                'destination_ip': flow.dst_ip,
                'source_port': str(flow.src_port),
                'destination_port': str(flow.dst_port),
                'protocol': flow.protocol,
                'anomaly_type': attack_type or 'unknown',
                'severity': 'high' if status == 'attack' else 'medium' if status == 'suspicious' else 'low',
                'confidence_score': float(probability),
                'raw_data': json.dumps({
                    'status': status,
                    'ml_probability': float(probability),
                    'attack_type': attack_type or 'none',
                    'pattern_scores': dict(pattern_scores) if pattern_scores else {},
                    'flow_stats': {
                        'packets': len(flow.packets),
                        'duration': getattr(flow, 'flow_duration', 0),
                        'bytes': sum(getattr(flow, 'packet_lengths', []))
                    },
                    'client_info': {
                        'client_id': self.client_id,
                        'server_connected': self.connected_to_server,
                        'timestamp': time.time()
                    }
                }),
                'is_confirmed': None,
                'false_positive': False
            }
            
            # Agregar a cola BD
            with self.queue_lock:
                self.detection_queue.append(detection_record)
    
    # === MÉTODOS DE BASE DE DATOS ===
    
    def _db_worker(self):
        """Hilo para guardar detecciones en BD local"""
        logger.info("[BD] Trabajador BD iniciado")
        
        while not self.stop_events['db'].is_set():
            try:
                # Recoger detecciones pendientes
                detections_to_save = []
                with self.queue_lock:
                    if self.detection_queue:
                        # Procesar en lotes pequeños
                        detections_to_save = self.detection_queue[:5]
                        self.detection_queue = self.detection_queue[5:]
                
                # Guardar en BD
                if detections_to_save:
                    self._save_detections_to_db(detections_to_save)
                
                # Esperar antes del siguiente ciclo
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"[BD] Error en trabajador BD: {e}")
                time.sleep(10)
    
    def _save_detections_to_db(self, detections):
        """Guarda detecciones en BD local"""
        if not DB_AVAILABLE:
            return
            
        conn = None
        try:
            conn = obtener_conexion()
            if not conn:
                # Devolver a cola si no hay conexión
                with self.queue_lock:
                    self.detection_queue = detections + self.detection_queue
                return
            
            with conn.cursor() as cursor:
                # Crear tabla de detecciones con PRIMARY KEY
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detections (
                        detection_id VARCHAR(255) PRIMARY KEY,
                        client_id INTEGER,
                        timestamp TIMESTAMP,
                        source_ip VARCHAR(45),
                        destination_ip VARCHAR(45),
                        source_port VARCHAR(10),
                        destination_port VARCHAR(10),
                        protocol VARCHAR(10),
                        anomaly_type VARCHAR(100),
                        severity VARCHAR(20),
                        confidence_score REAL,
                        raw_data TEXT,
                        is_confirmed BOOLEAN,
                        false_positive BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Insertar detecciones usando INSERT ... ON CONFLICT
                for detection in detections:
                    cursor.execute("""
                        INSERT INTO detections (
                            detection_id, client_id, timestamp, source_ip, destination_ip,
                            source_port, destination_port, protocol, anomaly_type,
                            severity, confidence_score, raw_data, is_confirmed, false_positive
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (detection_id) DO NOTHING
                    """, (
                        detection['detection_id'], detection['client_id'],
                        detection['timestamp'], detection['source_ip'],
                        detection['destination_ip'], detection['source_port'],
                        detection['destination_port'], detection['protocol'],
                        detection['anomaly_type'], detection['severity'],
                        detection['confidence_score'], detection['raw_data'],
                        detection['is_confirmed'], detection['false_positive']
                    ))
                
                conn.commit()
                logger.debug(f"[BD] Guardadas {len(detections)} detecciones")
                
        except Exception as e:
            logger.error(f"[BD] Error guardando: {e}")
            # Devolver a cola para reintento
            with self.queue_lock:
                self.detection_queue = detections + self.detection_queue
        finally:
            if conn:
                conn.close()
    
    def _flush_detection_queue(self):
        """Guarda todas las detecciones pendientes"""
        if not DB_AVAILABLE:
            return
            
        with self.queue_lock:
            if self.detection_queue:
                logger.info(f"[BD] Guardando {len(self.detection_queue)} detecciones pendientes...")
                self._save_detections_to_db(self.detection_queue)
                self.detection_queue.clear()
    
    # === MÉTODOS DE APRENDIZAJE FEDERADO ===
    
    def _federated_worker(self):
        """Hilo para comunicación con servidor federado"""
        logger.info("[FL] Trabajador federado iniciado")
        
        while not self.stop_events['federated'].is_set():
            try:
                self.federated_stats['connection_attempts'] += 1
                
                # Intentar conectar y mantener conexión
                asyncio.run(self._federated_connection())
                
            except Exception as e:
                logger.error(f"[FL] Error en conexión federada: {e}")
                
                # Esperar antes de reintentar (backoff exponencial)
                retry_delay = min(30, self.federated_stats['connection_attempts'] * 5)
                logger.info(f"[FL] Reintentando conexión en {retry_delay}s...")
                
                for _ in range(retry_delay):
                    if self.stop_events['federated'].is_set():
                        break
                    time.sleep(1)
    
    async def _federated_connection(self):
        """Mantiene conexión WebSocket con servidor federado"""
        try:
            logger.info(f"[FL] Conectando a servidor: {self.servidor_federado}")
            
            async with websockets.connect(
                self.servidor_federado,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=10,
                open_timeout=15
            ) as websocket:
                
                # Registrar cliente
                if not await self.register_client(websocket):
                    logger.error("[FL] No se pudo registrar en el servidor")
                    return
                
                self.connected_to_server = True
                self.federated_stats['connection_attempts'] = 0
                logger.info("[FL] Conectado al servidor federado")
                
                # Iniciar tareas asíncronas
                heartbeat_task = asyncio.create_task(self._heartbeat_worker(websocket))
                stats_task = asyncio.create_task(self._stats_sender(websocket))
                
                try:
                    # Bucle principal de comunicación
                    async for message in websocket:
                        if self.stop_events['federated'].is_set():
                            break
                        
                        try:
                            data = json.loads(message)
                            self.federated_stats['messages_received'] += 1
                            await self._handle_federated_message(data, websocket)
                        except json.JSONDecodeError:
                            logger.error("[FL] Mensaje con formato JSON inválido")
                        except Exception as e:
                            logger.error(f"[FL] Error procesando mensaje: {e}")
                            
                finally:
                    # Cancelar tareas
                    heartbeat_task.cancel()
                    stats_task.cancel()
                    
                    try:
                        await heartbeat_task
                        await stats_task
                    except asyncio.CancelledError:
                        pass
                    
        except websockets.exceptions.ConnectionClosedError:
            logger.warning("[FL] Conexión cerrada por el servidor")
        except (OSError, ConnectionRefusedError) as e:
            logger.warning(f"[FL] No se pudo conectar: {e}")
        except asyncio.TimeoutError:
            logger.warning("[FL] Timeout conectando al servidor")
        except Exception as e:
            logger.error(f"[FL] Error en conexión: {e}")
        finally:
            self.connected_to_server = False
    
    async def register_client(self, websocket):
        """Registra el cliente con el servidor federado"""
        try:
            registration_message = {
                'type': 'register',
                'client_info': {
                    'id': self.client_id,
                    'name': f'Cliente-Detector-{self.client_id}',
                    'location': 'PC Windows - Cliente Federado',
                    'interface': self.interface,
                    'capabilities': ['detection', 'learning', 'real_time'],
                    'version': '2.0',
                    'os': 'Windows',
                    'python_version': sys.version.split()[0],
                    'model_info': {
                        'type': type(self.model).__name__,
                        'features': len(self.selected_features) if self.selected_features else 'auto'
                    }
                }
            }
            
            await websocket.send(json.dumps(registration_message))
            self.federated_stats['messages_sent'] += 1
            logger.info("[FL] Mensaje de registro enviado")
            
            # Esperar confirmación
            response = await asyncio.wait_for(websocket.recv(), timeout=30)
            data = json.loads(response)
            
            if data.get('type') == 'registration_confirmed':
                self.server_assigned_id = data.get('client_id')
                server_info = data.get('server_info', {})
                
                logger.info(f"[FL] Registro confirmado - ID: {self.server_assigned_id}")
                logger.info(f"[FL] Servidor - Ronda: {server_info.get('current_round', 0)}, "
                           f"Clientes: {server_info.get('total_clients', 0)}")
                
                return True
            else:
                logger.error(f"[FL] Registro rechazado: {data.get('message', 'Razón desconocida')}")
                return False
                
        except asyncio.TimeoutError:
            logger.error("[FL] Timeout esperando confirmación de registro")
            return False
        except Exception as e:
            logger.error(f"[FL] Error en registro: {e}")
            return False
    
    async def _heartbeat_worker(self, websocket):
        """Envía heartbeats periódicos al servidor"""
        try:
            while not self.stop_events['federated'].is_set():
                heartbeat_msg = {
                    'type': 'heartbeat',
                    'client_id': self.server_assigned_id,
                    'status': 'active',
                    'timestamp': time.time(),
                    'stats': {
                        'uptime': time.time() - getattr(self, 'start_time', time.time()),
                        'packets_processed': getattr(self, 'performance_metrics', {}).get('packets_processed', 0),
                        'flows_analyzed': getattr(self, 'performance_metrics', {}).get('flows_analyzed', 0),
                        'detections_total': self.total_detections,
                        'detections_queue': len(self.detection_queue),
                        'alert_counts': getattr(self, 'alert_counts', {}),
                        'connected_to_db': DB_AVAILABLE
                    }
                }
                
                await websocket.send(json.dumps(heartbeat_msg))
                self.federated_stats['messages_sent'] += 1
                self.federated_stats['last_heartbeat'] = time.time()
                
                await asyncio.sleep(30)  # Heartbeat cada 30 segundos
                
        except asyncio.CancelledError:
            logger.debug("[FL] Heartbeat worker cancelado")
        except Exception as e:
            logger.error(f"[FL] Error en heartbeat: {e}")
    
    async def _stats_sender(self, websocket):
        """Envía estadísticas detalladas periódicamente"""
        try:
            while not self.stop_events['federated'].is_set():
                await asyncio.sleep(300)  # Estadísticas cada 5 minutos
                
                # Usar estadísticas del detector padre
                perf_metrics = getattr(self, 'performance_metrics', {})
                current_stats = {
                    'packets_processed': perf_metrics.get('packets_processed', 0),
                    'flows_analyzed': perf_metrics.get('flows_analyzed', 0),
                    'total_detections': self.total_detections,
                    'alert_distribution': getattr(self, 'alert_counts', {}),
                    'attack_types': getattr(self, 'attack_types', {}),
                    'uptime': time.time() - getattr(self, 'start_time', time.time()),
                    'active_flows': len(getattr(self, 'flows', {})),
                    'performance': {
                        'cpu_percent': psutil.cpu_percent(),
                        'memory_percent': psutil.virtual_memory().percent,
                        'interface': self.interface
                    },
                    'federated_stats': self.federated_stats.copy()
                }
                
                stats_msg = {
                    'type': 'stats_update',
                    'client_id': self.server_assigned_id,
                    'stats': current_stats,
                    'timestamp': time.time()
                }
                
                await websocket.send(json.dumps(stats_msg))
                self.federated_stats['messages_sent'] += 1
                logger.debug("[FL] Estadísticas enviadas al servidor")
                
        except asyncio.CancelledError:
            logger.debug("[FL] Stats sender cancelado")
        except Exception as e:
            logger.error(f"[FL] Error enviando estadísticas: {e}")
    
    async def _handle_federated_message(self, data: Dict[str, Any], websocket):
        """Maneja mensajes del servidor federado"""
        msg_type = data.get('type')
        
        if msg_type == 'heartbeat_ack':
            logger.debug("[FL] Heartbeat confirmado")
            
        elif msg_type == 'global_model_update':
            logger.info("[FL] Recibiendo actualización de modelo global")
            self.federated_stats['model_updates_received'] += 1
            
        elif msg_type == 'client_joined':
            client_info = data.get('client_info', {})
            logger.info(f"[FL] Nuevo cliente: {client_info.get('name', 'Unknown')}")
            
        elif msg_type == 'client_left':
            client_name = data.get('client_name', 'Unknown')
            logger.info(f"[FL] Cliente desconectado: {client_name}")
            
        elif msg_type == 'critical_alert':
            alert = data.get('alert', {})
            logger.warning(f"[ALERT] {alert.get('src_ip')} -> {alert.get('dst_ip')}")
            
        elif msg_type == 'aggregation_request':
            logger.info("[FL] Servidor solicita participación en agregación")
            self.rounds_participated += 1
            
        elif msg_type == 'server_message':
            message = data.get('message', '')
            logger.info(f"[FL] Mensaje del servidor: {message}")
            
        else:
            logger.debug(f"[FL] Mensaje desconocido: {msg_type}")
    
    def get_status(self):
        """Retorna estado completo del cliente federado"""
        return {
            'client_id': self.client_id,
            'server_assigned_id': self.server_assigned_id,
            'connected_to_server': self.connected_to_server,
            'servidor_federado': self.servidor_federado,
            'last_model_update': self.last_model_update,
            'rounds_participated': self.rounds_participated,
            'detections_pending': len(self.detection_queue),
            'total_detections': self.total_detections,
            'db_available': DB_AVAILABLE,
            'federated_stats': self.federated_stats.copy(),
            'detection_counts': getattr(self, 'alert_counts', {'normal': 0, 'suspicious': 0, 'attack': 0}),
            'performance_metrics': getattr(self, 'performance_metrics', {}),
            'uptime': time.time() - getattr(self, 'start_time', time.time())
        }


def run_cliente_federado(model_path, interface, client_id=1, servidor_federado="ws://192.168.1.100:8765"):
    """Ejecuta el cliente federado detector"""
    try:
        print("=" * 70)
        print("CLIENTE FEDERADO DETECTOR DE INTRUSIONES")
        print("=" * 70)
        
        # Configurar logging para Windows
        setup_windows_logging()
        
        # Verificar modelo
        if not os.path.exists(model_path):
            print(f"ERROR: Modelo no encontrado: {model_path}")
            print("Verifique que el archivo modelo_rf.pkl existe")
            return
        
        # Verificar conectividad BD
        if DB_AVAILABLE:
            try:
                conn = obtener_conexion()
                if conn:
                    conn.close()
                    print("Base de datos: CONECTADA")
                else:
                    print("Base de datos: NO DISPONIBLE (continuará sin BD)")
            except:
                print("Base de datos: ERROR DE CONEXIÓN (continuará sin BD)")
        else:
            print("Base de datos: MÓDULO NO DISPONIBLE")
        
        # Crear cliente
        cliente = ClienteFederadoDetector(
            model_path=model_path,
            interface=interface, 
            client_id=client_id,
            servidor_federado=servidor_federado
        )
        
        # Mostrar información
        print(f"Cliente ID: {client_id}")
        print(f"Interfaz de red: {interface}")
        print(f"Modelo ML: {model_path}")
        print(f"Servidor Federado: {servidor_federado}")
        print("-" * 70)
        print("Iniciando cliente... (Ctrl+C para detener)")
        print("-" * 70)
        
        # Iniciar
        cliente.start_capture()
        
        # Ejecutar hasta interrupción
        try:
            start_time = time.time()
            update_interval = 30  # Actualizar estado cada 30 segundos
            
            while True:
                time.sleep(update_interval)
                
                # Obtener y mostrar estado
                status = cliente.get_status()
                uptime = int(time.time() - start_time)
                
                # Indicador de conexión
                if status['connected_to_server']:
                    connection_status = f"CONECTADO (ID: {status['server_assigned_id']})"
                else:
                    connection_status = "DESCONECTADO"
                
                # Mostrar estado
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Estado del Cliente:")
                print(f"  Tiempo activo: {uptime}s")
                print(f"  Servidor federado: {connection_status}")
                print(f"  Rondas FL participadas: {status['rounds_participated']}")
                print(f"  Detecciones totales: {status['total_detections']}")
                print(f"  Cola BD: {status['detections_pending']} pendientes")
                print(f"  Distribución alertas: {status['detection_counts']}")
                
                # Estadísticas federadas
                fed_stats = status['federated_stats']
                print(f"  Msgs enviados/recibidos: {fed_stats['messages_sent']}/{fed_stats['messages_received']}")
                print(f"  Actualizaciones modelo: {fed_stats['model_updates_received']}")
                
        except KeyboardInterrupt:
            print("\n" + "=" * 70)
            print("DETENIENDO CLIENTE FEDERADO...")
            print("=" * 70)
            
            # Obtener estadísticas finales
            final_status = cliente.get_status()
            
            print("ESTADÍSTICAS FINALES:")
            print(f"  Tiempo total activo: {int(final_status['uptime'])}s")
            print(f"  Detecciones procesadas: {final_status['total_detections']}")
            print(f"  Rondas FL participadas: {final_status['rounds_participated']}")
            print(f"  Mensajes federados enviados: {final_status['federated_stats']['messages_sent']}")
            
            # Detener cliente
            cliente.stop_capture_threads()
        
        print("Cliente federado detenido correctamente")
        
    except Exception as e:
        print(f"ERROR ejecutando cliente federado: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cliente Federado Detector de Intrusiones")
    parser.add_argument("--model", default="model/modelo_rf.pkl", 
                       help="Ruta del modelo ML")
    parser.add_argument("--interface", default="Ethernet", 
                       help="Interfaz de red")
    parser.add_argument("--client-id", type=int, default=1, 
                       help="ID único del cliente")
    parser.add_argument("--server", default="ws://192.168.1.100:8765", 
                       help="URL del servidor federado")
    
    args = parser.parse_args()
    
    run_cliente_federado(args.model, args.interface, args.client_id, args.server)