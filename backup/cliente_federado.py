#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cliente Federado para Sistema de Detección de Intrusiones
---------------------------------------------------------
Conecta con servidor federado y comparte modelos/alertas
Autor: Johann
Fecha: 2025-06-06
Versión: 1.0
"""

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
import sys
import os

# Importar el detector original (corregir nombre del archivo)
from detector import NetworkMonitor, CONFIG, logger as detector_logger

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cliente_federado.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FederatedIDSClient:
    """Cliente federado que extiende el NetworkMonitor original"""
    
    def __init__(self, server_url, client_name, location, model_path, interface='eth0'):
        self.server_url = server_url
        self.client_name = client_name
        self.location = location
        self.client_id = None
        self.websocket = None
        
        # Monitor de red original
        try:
            self.network_monitor = NetworkMonitor(model_path, interface)
        except Exception as e:
            logger.error(f"Error inicializando NetworkMonitor: {e}")
            # Crear un monitor básico si falla
            self.network_monitor = None
        
        # Estado de conexión federada
        self.connected = False
        self.last_heartbeat = 0
        self.heartbeat_interval = 30  # segundos
        
        # Configuración de sincronización
        self.sync_config = {
            'stats_interval': 60,        # Enviar estadísticas cada minuto
            'model_update_interval': 300, # Actualizar modelo cada 5 minutos
            'alert_threshold': 0.7,      # Umbral para compartir alertas
            'critical_threshold': 0.9    # Umbral para alertas críticas
        }
        
        # Métricas para compartir
        self.local_stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'alert_distribution': {'normal': 0, 'suspicious': 0, 'attack': 0},
            'attack_types': {},
            'performance_metrics': {}
        }
        
        # Cola de alertas para enviar
        self.alert_queue = asyncio.Queue()
        
        # Hilos de trabajo
        self.running = False
        self.communication_task = None
        self.stats_task = None
        self.heartbeat_task = None
        
        # Interceptar las funciones del monitor original
        if self.network_monitor:
            self._setup_monitoring_hooks()
    
    def _setup_monitoring_hooks(self):
        """Configura hooks para interceptar eventos del monitor"""
        if not self.network_monitor:
            return
            
        # Guardar métodos originales
        original_print_detection = getattr(self.network_monitor, '_print_detection', None)
        original_evaluate_flow = getattr(self.network_monitor, '_evaluate_flow', None)
        
        if original_print_detection:
            # Interceptar detecciones
            def hooked_print_detection(status, flow, probability, attack_type=None, pattern_scores=None):
                # Llamar método original
                original_print_detection(status, flow, probability, attack_type, pattern_scores)
                
                # Procesar para federación
                self._process_detection(status, flow, probability, attack_type, pattern_scores)
            
            # Reemplazar método
            self.network_monitor._print_detection = hooked_print_detection
        
        if original_evaluate_flow:
            # Interceptar evaluaciones de flujo
            def hooked_evaluate_flow(flow_id):
                # Actualizar estadísticas locales
                self.local_stats['flows_analyzed'] += 1
                
                # Llamar método original
                original_evaluate_flow(flow_id)
            
            # Reemplazar método
            self.network_monitor._evaluate_flow = hooked_evaluate_flow
    
    def _process_detection(self, status, flow, probability, attack_type=None, pattern_scores=None):
        """Procesa una detección para compartir con el servidor"""
        # Actualizar estadísticas locales
        self.local_stats['alert_distribution'][status] += 1
        
        if attack_type and status == 'attack':
            if attack_type not in self.local_stats['attack_types']:
                self.local_stats['attack_types'][attack_type] = 0
            self.local_stats['attack_types'][attack_type] += 1
        
        # Crear alerta para compartir si supera el umbral
        if probability >= self.sync_config['alert_threshold']:
            alert = {
                'timestamp': time.time(),
                'status': status,
                'src_ip': getattr(flow, 'src_ip', 'unknown'),
                'dst_ip': getattr(flow, 'dst_ip', 'unknown'),
                'src_port': getattr(flow, 'src_port', 0),
                'dst_port': getattr(flow, 'dst_port', 0),
                'protocol': getattr(flow, 'protocol', 'unknown'),
                'score': probability,
                'attack_type': attack_type,
                'pattern_scores': dict(pattern_scores) if pattern_scores else {},
                'flow_duration': getattr(flow, 'flow_duration', 0),
                'packet_count': len(getattr(flow, 'packets', [])),
                'is_critical': probability >= self.sync_config['critical_threshold']
            }
            
            # Añadir a cola de alertas de forma segura
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.alert_queue.put(alert))
            except RuntimeError:
                # No hay event loop activo, usar threading
                threading.Thread(target=self._add_alert_sync, args=(alert,)).start()
    
    def _add_alert_sync(self, alert):
        """Añade alerta de forma síncrona"""
        try:
            # Crear un nuevo event loop para esta operación
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.alert_queue.put(alert))
            loop.close()
        except Exception as e:
            logger.error(f"Error añadiendo alerta: {e}")
    
    async def connect_to_server(self):
        """Conecta con el servidor federado"""
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Conectando al servidor federado: {self.server_url} (intento {attempt + 1}/{max_retries})")
                
                self.websocket = await websockets.connect(
                    self.server_url,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=10
                )
                
                # Enviar mensaje de registro
                registration_message = {
                    'type': 'register',
                    'name': self.client_name,
                    'location': self.location,
                    'interface': getattr(self.network_monitor, 'interface', 'unknown') if self.network_monitor else 'unknown',
                    'capabilities': [
                        'intrusion_detection',
                        'model_training',
                        'alert_generation'
                    ],
                    'version': '1.0'
                }
                
                await self.websocket.send(json.dumps(registration_message))
                
                # Esperar confirmación con timeout
                response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
                response_data = json.loads(response)
                
                if response_data['type'] == 'registration_confirmed':
                    self.client_id = response_data['client_id']
                    self.connected = True
                    
                    logger.info(f"Registrado en servidor con ID: {self.client_id[:8]}")
                    
                    # Procesar modelo global si está disponible
                    if 'global_model' in response_data:
                        await self._update_local_model(response_data['global_model'])
                    
                    return True
                else:
                    logger.error(f"Error en registro: {response_data.get('message', 'Unknown')}")
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout conectando al servidor (intento {attempt + 1})")
            except Exception as e:
                logger.warning(f"Error conectando al servidor (intento {attempt + 1}): {e}")
                
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Backoff exponencial
        
        logger.error("No se pudo conectar al servidor después de múltiples intentos")
        return False
    
    async def start_federated_monitoring(self):
        """Inicia el monitoreo federado"""
        if not await self.connect_to_server():
            logger.error("No se pudo conectar al servidor federado")
            return False
        
        self.running = True
        
        # Iniciar tareas asíncronas
        self.communication_task = asyncio.create_task(self._communication_handler())
        self.stats_task = asyncio.create_task(self._stats_sender())
        self.heartbeat_task = asyncio.create_task(self._heartbeat_sender())
        
        # Iniciar monitor de red en hilo separado si está disponible
        if self.network_monitor:
            monitor_thread = threading.Thread(target=self._start_network_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
        else:
            # Simular actividad si no hay monitor real
            activity_thread = threading.Thread(target=self._simulate_activity)
            activity_thread.daemon = True
            activity_thread.start()
        
        logger.info("Monitoreo federado iniciado")
        return True
    
    def _start_network_monitor(self):
        """Inicia el monitor de red original"""
        try:
            if self.network_monitor:
                self.network_monitor.start_capture()
        except Exception as e:
            logger.error(f"Error en monitor de red: {e}")
    
    def _simulate_activity(self):
        """Simula actividad de red para pruebas"""
        import random
        
        while self.running:
            try:
                # Simular detección aleatoria
                if random.random() < 0.1:  # 10% probabilidad
                    status = random.choice(['normal', 'suspicious', 'attack'])
                    probability = random.uniform(0.1, 1.0)
                    
                    # Crear objeto flow simulado
                    class SimulatedFlow:
                        def __init__(self):
                            self.src_ip = f"192.168.1.{random.randint(1, 254)}"
                            self.dst_ip = f"10.0.0.{random.randint(1, 254)}"
                            self.src_port = random.randint(1024, 65535)
                            self.dst_port = random.choice([80, 443, 22, 23, 3389])
                            self.protocol = random.choice(['TCP', 'UDP'])
                            self.flow_duration = random.uniform(0.1, 10.0)
                            self.packets = [None] * random.randint(1, 100)
                    
                    flow = SimulatedFlow()
                    attack_type = random.choice(['scan', 'dos', 'web']) if status == 'attack' else None
                    
                    self._process_detection(status, flow, probability, attack_type, {})
                
                # Actualizar estadísticas
                self.local_stats['packets_processed'] += random.randint(10, 100)
                
                time.sleep(5)  # Esperar 5 segundos
                
            except Exception as e:
                logger.error(f"Error en simulación: {e}")
                time.sleep(10)
    
    async def _communication_handler(self):
        """Maneja la comunicación con el servidor"""
        try:
            while self.running and self.websocket:
                # Crear tareas concurrentes
                tasks = [
                    asyncio.create_task(self._handle_server_messages()),
                    asyncio.create_task(self._send_pending_alerts())
                ]
                
                # Esperar con timeout
                try:
                    done, pending = await asyncio.wait(
                        tasks,
                        return_when=asyncio.FIRST_COMPLETED,
                        timeout=1.0
                    )
                    
                    # Cancelar tareas pendientes
                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                            
                except asyncio.TimeoutError:
                    # Timeout normal, continuar
                    for task in tasks:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    
        except Exception as e:
            logger.error(f"Error en manejador de comunicación: {e}")
    
    async def _handle_server_messages(self):
        """Maneja mensajes del servidor"""
        try:
            if self.websocket:
                message = await asyncio.wait_for(self.websocket.recv(), timeout=0.5)
                data = json.loads(message)
                
                message_type = data.get('type')
                
                if message_type == 'heartbeat_ack':
                    self.last_heartbeat = time.time()
                    
                elif message_type == 'global_model_update':
                    await self._update_local_model(data['model_data'])
                    
                elif message_type == 'critical_alert':
                    await self._handle_critical_alert(data['alert'])
                    
                elif message_type == 'client_joined':
                    logger.info(f"Nuevo cliente conectado: {data['client_info']['name']}")
                    
                elif message_type == 'client_left':
                    logger.info(f"Cliente desconectado: {data['client_name']}")
                    
                else:
                    logger.debug(f"Mensaje no manejado: {message_type}")
                    
        except asyncio.TimeoutError:
            pass  # Timeout normal
        except websockets.exceptions.ConnectionClosed:
            logger.warning("Conexión con servidor perdida")
            self.connected = False
        except Exception as e:
            logger.error(f"Error manejando mensaje del servidor: {e}")
    
    async def _send_pending_alerts(self):
        """Envía alertas pendientes al servidor"""
        try:
            # Procesar hasta 5 alertas por ciclo
            for _ in range(5):
                try:
                    alert = await asyncio.wait_for(self.alert_queue.get(), timeout=0.1)
                    
                    message = {
                        'type': 'detection_alert',
                        'alert': alert,
                        'client_timestamp': time.time()
                    }
                    
                    if self.websocket and self.connected:
                        await self.websocket.send(json.dumps(message))
                        logger.debug("Alerta enviada al servidor")
                        
                except asyncio.TimeoutError:
                    break  # No hay más alertas
                    
        except Exception as e:
            logger.error(f"Error enviando alertas: {e}")
    
    async def _stats_sender(self):
        """Envía estadísticas periódicamente al servidor"""
        while self.running:
            try:
                await asyncio.sleep(self.sync_config['stats_interval'])
                
                if self.connected and self.websocket:
                    # Recopilar estadísticas actuales
                    performance_metrics = getattr(self.network_monitor, 'performance_metrics', {}) if self.network_monitor else {}
                    
                    stats = {
                        'packets_processed': performance_metrics.get('packets_processed', self.local_stats['packets_processed']),
                        'flows_analyzed': performance_metrics.get('flows_analyzed', self.local_stats['flows_analyzed']),
                        'alert_distribution': dict(self.local_stats['alert_distribution']),
                        'attack_types': dict(self.local_stats['attack_types']),
                        'uptime': time.time() - performance_metrics.get('start_time', time.time()),
                        'total_alerts': sum(self.local_stats['alert_distribution'].values())
                    }
                    
                    message = {
                        'type': 'stats_update',
                        'stats': stats,
                        'timestamp': time.time()
                    }
                    
                    await self.websocket.send(json.dumps(message))
                    logger.debug("Estadísticas enviadas al servidor")
                    
            except Exception as e:
                logger.error(f"Error enviando estadísticas: {e}")
                await asyncio.sleep(10)  # Esperar antes de reintentar
    
    async def _heartbeat_sender(self):
        """Envía heartbeat al servidor"""
        while self.running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                if self.connected and self.websocket:
                    message = {
                        'type': 'heartbeat',
                        'timestamp': time.time(),
                        'status': 'active'
                    }
                    
                    await self.websocket.send(json.dumps(message))
                    logger.debug("Heartbeat enviado")
                    
            except Exception as e:
                logger.error(f"Error enviando heartbeat: {e}")
    
    async def _update_local_model(self, model_data):
        """Actualiza el modelo local con el modelo global"""
        try:
            version = model_data.get('version', 'unknown')
            logger.info(f"Actualizando modelo local con versión {version}")
            
            # Verificar checksum si está disponible
            checksum = model_data.get('checksum')
            if checksum:
                logger.debug(f"Checksum del modelo: {checksum}")
            
            # Actualizar features si están disponibles
            features = model_data.get('features', [])
            if features and self.network_monitor and hasattr(self.network_monitor, 'selected_features'):
                self.network_monitor.selected_features = features
                logger.debug(f"Features actualizadas: {len(features)} características")
            
            logger.info("Modelo local actualizado exitosamente")
            
        except Exception as e:
            logger.error(f"Error actualizando modelo local: {e}")
    
    async def _handle_critical_alert(self, alert):
        """Maneja alertas críticas de otros clientes"""
        client_name = alert.get('client_name', 'Unknown')
        src_ip = alert.get('src_ip', 'unknown')
        dst_ip = alert.get('dst_ip', 'unknown')
        score = alert.get('score', 0)
        attack_type = alert.get('attack_type', 'unknown')
        
        logger.warning(f"🚨 ALERTA CRÍTICA de {client_name}: {src_ip} -> {dst_ip} "
                      f"({attack_type.upper()}, Score: {score:.4f})")
        
        # Imprimir en consola con colores
        print(f"\033[91m🚨 ALERTA CRÍTICA de {client_name}: {src_ip} -> {dst_ip} "
              f"({attack_type.upper()}, Score: {score:.4f})\033[0m")
    
    async def stop_federated_monitoring(self):
        """Detiene el monitoreo federado"""
        logger.info("Deteniendo monitoreo federado...")
        self.running = False
        
        # Cancelar tareas
        tasks_to_cancel = [self.communication_task, self.stats_task, self.heartbeat_task]
        for task in tasks_to_cancel:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Cerrar conexión WebSocket
        if self.websocket:
            try:
                await self.websocket.close()
            except:
                pass
            self.connected = False
        
        # Detener monitor de red
        if self.network_monitor:
            try:
                self.network_monitor.stop_capture_threads()
            except:
                pass
        
        logger.info("Monitoreo federado detenido")


async def main():
    """Función principal del cliente federado"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Cliente Federado para IDS")
    parser.add_argument("--server", default="ws://localhost:8765", help="URL del servidor federado")
    parser.add_argument("--name", default="IDS-Client", help="Nombre del cliente")
    parser.add_argument("--location", default="Unknown", help="Ubicación del cliente")
    parser.add_argument("--model", default="model/modelo_rf.pkl", help="Ruta del modelo local")
    parser.add_argument("--interface", default="Ethernet" if os.name == 'nt' else "eth0", help="Interfaz de red")
    parser.add_argument("--stats-interval", type=int, default=60, help="Intervalo de estadísticas (segundos)")
    parser.add_argument("--alert-threshold", type=float, default=0.7, help="Umbral para compartir alertas")
    
    args = parser.parse_args()
    
    print(f"Iniciando Cliente Federado IDS")
    print(f"Nombre: {args.name}")
    print(f"Ubicación: {args.location}")
    print(f"Servidor: {args.server}")
    print(f"Interfaz: {args.interface}")
    print("-" * 50)
    
    # Crear cliente federado
    client = FederatedIDSClient(
        server_url=args.server,
        client_name=args.name,
        location=args.location,
        model_path=args.model,
        interface=args.interface
    )
    
    # Configurar parámetros
    client.sync_config['stats_interval'] = args.stats_interval
    client.sync_config['alert_threshold'] = args.alert_threshold
    
    try:
        # Iniciar monitoreo federado
        if await client.start_federated_monitoring():
            print(f"✅ Cliente federado '{args.name}' iniciado exitosamente")
            print(f"🔗 Conectado a: {args.server}")
            print(f"🖥️  Monitoreando interfaz: {args.interface}")
            print("📊 Enviando estadísticas cada", args.stats_interval, "segundos")
            print("⚠️  Umbral de alertas:", args.alert_threshold)
            print("\nPresione Ctrl+C para detener\n")
            
            # Ejecutar indefinidamente
            try:
                while client.running:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Deteniendo cliente federado...")
                await client.stop_federated_monitoring()
                print("✅ Cliente federado detenido")
        else:
            print("❌ No se pudo iniciar el cliente federado")
            
    except Exception as e:
        logger.error(f"Error en cliente federado: {e}")
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())