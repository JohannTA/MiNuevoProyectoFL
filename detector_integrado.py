#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detector Integrado con Sistema Federado
---------------------------------------
Basado en detectorv9v1.py pero integrado con BD y servidor federado
"""

import asyncio
import logging
import threading
import time
import json
import uuid
from datetime import datetime
from collections import defaultdict, deque, Counter
import numpy as np
import pandas as pd
import pyshark
import joblib
from pathlib import Path
from psycopg2.extras import RealDictCursor

# Importaciones para BD
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración del detector
CONFIG = {
    'NORMAL_THRESHOLD': 0.3,
    'SUSPICIOUS_THRESHOLD': 0.7,
    'SHOW_NORMAL_TRAFFIC': False,
    'UPDATE_INTERVAL': 10,
    'FLOW_TIMEOUT': 30,
    'MAX_FLOWS': 1000,
    'DB_BATCH_SIZE': 10,
    'COLORS': {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'RESET': '\033[0m'
    }
}

class FlowRecord:
    """Registro de flujo de red mejorado"""
    
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Métricas básicas
        self.packets = []
        self.bytes_sent = 0
        self.bytes_received = 0
        self.flow_duration = 0
        self.start_time = time.time()
        self.last_activity = time.time()
        
        # Métricas avanzadas
        self.tcp_flags = defaultdict(int)
        self.packet_sizes = []
        self.inter_arrival_times = []
        self.ports_contacted = set()
        self.http_methods = Counter()
        self.dns_queries = []
        
        # Patrones de comportamiento
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.unique_ports = set()
        self.payload_sizes = []
        
    def add_packet(self, packet):
        """Agrega un paquete al flujo"""
        current_time = time.time()
        
        # Calcular tiempo entre arribos
        if self.packets:
            inter_arrival = current_time - self.last_activity
            self.inter_arrival_times.append(inter_arrival)
        
        self.packets.append({
            'timestamp': current_time,
            'size': getattr(packet, 'length', 0),
            'flags': self._extract_tcp_flags(packet)
        })
        
        # Actualizar métricas
        packet_size = int(getattr(packet, 'length', 0))
        self.packet_sizes.append(packet_size)
        self.bytes_sent += packet_size
        
        # Analizar banderas TCP
        if hasattr(packet, 'tcp'):
            self._analyze_tcp_flags(packet.tcp)
        
        # Analizar HTTP
        if hasattr(packet, 'http'):
            self._analyze_http(packet.http)
        
        # Analizar DNS
        if hasattr(packet, 'dns'):
            self._analyze_dns(packet.dns)
        
        # Actualizar tiempos
        self.last_activity = current_time
        self.flow_duration = current_time - self.start_time
        
        # Agregar puerto destino a conjunto
        self.unique_ports.add(self.dst_port)
    
    def _extract_tcp_flags(self, packet):
        """Extrae banderas TCP del paquete"""
        flags = {}
        if hasattr(packet, 'tcp'):
            tcp = packet.tcp
            flags['syn'] = int(getattr(tcp, 'flags_syn', 0))
            flags['ack'] = int(getattr(tcp, 'flags_ack', 0))
            flags['rst'] = int(getattr(tcp, 'flags_reset', 0))
            flags['fin'] = int(getattr(tcp, 'flags_fin', 0))
            flags['psh'] = int(getattr(tcp, 'flags_push', 0))
        return flags
    
    def _analyze_tcp_flags(self, tcp):
        """Analiza banderas TCP"""
        if hasattr(tcp, 'flags_syn') and int(tcp.flags_syn):
            self.syn_count += 1
        if hasattr(tcp, 'flags_ack') and int(tcp.flags_ack):
            self.ack_count += 1
        if hasattr(tcp, 'flags_reset') and int(tcp.flags_reset):
            self.rst_count += 1
    
    def _analyze_http(self, http):
        """Analiza tráfico HTTP"""
        if hasattr(http, 'request_method'):
            method = str(http.request_method)
            self.http_methods[method] += 1
    
    def _analyze_dns(self, dns):
        """Analiza consultas DNS"""
        if hasattr(dns, 'qry_name'):
            query = str(dns.qry_name)
            self.dns_queries.append(query)
    
    def get_features(self):
        """Extrae características para ML"""
        if not self.packets:
            return {}
        
        # Estadísticas básicas
        packet_count = len(self.packets)
        total_bytes = sum(self.packet_sizes) if self.packet_sizes else 0
        
        # Estadísticas de tiempo
        avg_inter_arrival = np.mean(self.inter_arrival_times) if self.inter_arrival_times else 0
        std_inter_arrival = np.std(self.inter_arrival_times) if len(self.inter_arrival_times) > 1 else 0
        
        # Estadísticas de tamaño
        avg_packet_size = np.mean(self.packet_sizes) if self.packet_sizes else 0
        std_packet_size = np.std(self.packet_sizes) if len(self.packet_sizes) > 1 else 0
        min_packet_size = min(self.packet_sizes) if self.packet_sizes else 0
        max_packet_size = max(self.packet_sizes) if self.packet_sizes else 0
        
        # Ratios y tasas
        bytes_per_second = total_bytes / max(self.flow_duration, 0.001)
        packets_per_second = packet_count / max(self.flow_duration, 0.001)
        
        # Características de protocolo
        syn_ratio = self.syn_count / max(packet_count, 1)
        ack_ratio = self.ack_count / max(packet_count, 1)
        rst_ratio = self.rst_count / max(packet_count, 1)
        
        return {
            # Básicas
            'flow_duration': self.flow_duration,
            'packet_count': packet_count,
            'total_bytes': total_bytes,
            'unique_ports': len(self.unique_ports),
            
            # Ratios y tasas
            'bytes_per_second': bytes_per_second,
            'packets_per_second': packets_per_second,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': std_packet_size,
            'min_packet_size': min_packet_size,
            'max_packet_size': max_packet_size,
            
            # Tiempo
            'avg_inter_arrival': avg_inter_arrival,
            'std_inter_arrival': std_inter_arrival,
            
            # TCP
            'syn_count': self.syn_count,
            'ack_count': self.ack_count,
            'rst_count': self.rst_count,
            'syn_ratio': syn_ratio,
            'ack_ratio': ack_ratio,
            'rst_ratio': rst_ratio,
            
            # Comportamiento
            'http_methods_count': len(self.http_methods),
            'dns_queries_count': len(self.dns_queries),
            'port_scan_indicator': len(self.unique_ports) / max(packet_count, 1)
        }

class DetectorIntegrado:
    """Detector de intrusiones integrado con BD y servidor federado"""
    
    def __init__(self, model_path, interface, client_id=None):
        self.model_path = model_path
        self.interface = interface
        self.client_id = client_id or 1  # ID del cliente en BD
        
        # Estado del detector
        self.running = False
        self.capture = None
        self.flows = {}
        self.flow_lock = threading.Lock()
        
        # Modelo ML
        self.model = None
        self.scaler = None
        self.selected_features = []
        self.load_model()
        
        # Estadísticas
        self.stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'detections_normal': 0,
            'detections_suspicious': 0,
            'detections_attack': 0,
            'start_time': time.time()
        }
        
        # Cola de detecciones para BD
        self.detection_queue = deque()
        self.detection_batch = []
        
        # Hilos
        self.capture_thread = None
        self.evaluation_thread = None
        self.database_thread = None
        self.stats_thread = None
    
    def load_model(self):
        """Carga el modelo ML"""
        try:
            if Path(self.model_path).exists():
                model_data = joblib.load(self.model_path)
                
                if isinstance(model_data, dict):
                    self.model = model_data.get('model')
                    self.scaler = model_data.get('scaler')
                    self.selected_features = model_data.get('selected_features', [])
                else:
                    self.model = model_data
                    self.scaler = None
                    self.selected_features = []
                
                logger.info(f"✅ Modelo cargado: {self.model_path}")
                if self.selected_features:
                    logger.info(f"📊 Características seleccionadas: {len(self.selected_features)}")
            else:
                logger.warning(f"⚠️  Modelo no encontrado: {self.model_path}")
                
        except Exception as e:
            logger.error(f"❌ Error cargando modelo: {e}")
            self.model = None
    
    def start_detection(self):
        """Inicia la detección de intrusiones"""
        if self.running:
            logger.warning("⚠️  Detector ya está en ejecución")
            return
        
        try:
            logger.info(f"🚀 Iniciando detector en interfaz: {self.interface}")
            
            # Crear captura de pyshark
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter="ip"  # Solo tráfico IP
            )
            
            self.running = True
            
            # Iniciar hilos
            self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
            self.evaluation_thread = threading.Thread(target=self._evaluation_worker, daemon=True)
            self.database_thread = threading.Thread(target=self._database_worker, daemon=True)
            self.stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
            
            self.capture_thread.start()
            self.evaluation_thread.start()
            self.database_thread.start()
            self.stats_thread.start()
            
            logger.info("✅ Detector iniciado exitosamente")
            
        except Exception as e:
            logger.error(f"❌ Error iniciando detector: {e}")
            self.running = False
    
    def stop_detection(self):
        """Detiene la detección"""
        logger.info("🛑 Deteniendo detector...")
        self.running = False
        
        if self.capture:
            try:
                self.capture.close()
            except:
                pass
        
        # Procesar detecciones pendientes
        self._flush_detections_to_db()
        
        logger.info("✅ Detector detenido")
    
    def _capture_worker(self):
        """Hilo para captura de paquetes"""
        try:
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                
                try:
                    self._process_packet(packet)
                    self.stats['packets_processed'] += 1
                except Exception as e:
                    logger.error(f"Error procesando paquete: {e}")
                    
        except Exception as e:
            logger.error(f"Error en captura: {e}")
    
    def _process_packet(self, packet):
        """Procesa un paquete individual"""
        try:
            # Extraer información básica
            if not hasattr(packet, 'ip'):
                return
            
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            
            if not protocol:
                return
            
            # Obtener puertos
            if hasattr(packet, protocol.lower()):
                transport = getattr(packet, protocol.lower())
                src_port = int(getattr(transport, 'srcport', 0))
                dst_port = int(getattr(transport, 'dstport', 0))
            else:
                src_port = dst_port = 0
            
            # Crear clave de flujo
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            
            with self.flow_lock:
                # Crear o actualizar flujo
                if flow_key not in self.flows:
                    self.flows[flow_key] = FlowRecord(src_ip, src_port, dst_ip, dst_port, protocol)
                
                self.flows[flow_key].add_packet(packet)
                
                # Limpiar flujos antiguos
                self._cleanup_old_flows()
                
        except Exception as e:
            logger.error(f"Error procesando paquete: {e}")
    
    def _cleanup_old_flows(self):
        """Limpia flujos antiguos"""
        current_time = time.time()
        expired_flows = []
        
        for flow_key, flow in self.flows.items():
            if current_time - flow.last_activity > CONFIG['FLOW_TIMEOUT']:
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            # Evaluar flujo antes de eliminarlo
            self._evaluate_flow(flow_key)
            del self.flows[flow_key]
        
        # Limitar número máximo de flujos
        if len(self.flows) > CONFIG['MAX_FLOWS']:
            # Eliminar los más antiguos
            sorted_flows = sorted(
                self.flows.items(),
                key=lambda x: x[1].last_activity
            )
            
            for flow_key, _ in sorted_flows[:len(self.flows) - CONFIG['MAX_FLOWS']]:
                self._evaluate_flow(flow_key)
                del self.flows[flow_key]
    
    def _evaluation_worker(self):
        """Hilo para evaluación de flujos"""
        while self.running:
            try:
                time.sleep(5)  # Evaluar cada 5 segundos
                
                with self.flow_lock:
                    current_time = time.time()
                    flows_to_evaluate = []
                    
                    for flow_key, flow in self.flows.items():
                        # Evaluar flujos que han estado activos por un tiempo
                        if (current_time - flow.start_time > 10 and 
                            len(flow.packets) >= 5):
                            flows_to_evaluate.append(flow_key)
                    
                    for flow_key in flows_to_evaluate:
                        self._evaluate_flow(flow_key)
                        
            except Exception as e:
                logger.error(f"Error en evaluación: {e}")
                time.sleep(5)
    
    def _evaluate_flow(self, flow_key):
        """Evalúa un flujo individual"""
        try:
            if flow_key not in self.flows:
                return
            
            flow = self.flows[flow_key]
            features = flow.get_features()
            
            if not features or not self.model:
                return
            
            # Preparar características para el modelo
            if self.selected_features:
                # Usar características seleccionadas
                feature_vector = []
                for feature_name in self.selected_features:
                    feature_vector.append(features.get(feature_name, 0))
            else:
                # Usar todas las características disponibles
                feature_vector = list(features.values())
            
            if not feature_vector:
                return
            
            # Convertir a array numpy
            X = np.array([feature_vector])
            
            # Aplicar escalado si está disponible
            if self.scaler:
                X = self.scaler.transform(X)
            
            # Predicción
            try:
                prediction_proba = self.model.predict_proba(X)[0]
                attack_probability = prediction_proba[1] if len(prediction_proba) > 1 else prediction_proba[0]
            except:
                # Fallback si predict_proba no está disponible
                prediction = self.model.predict(X)[0]
                attack_probability = float(prediction)
            
            # Clasificar según umbrales
            if attack_probability < CONFIG['NORMAL_THRESHOLD']:
                status = 'normal'
                severity = 'low'
            elif attack_probability < CONFIG['SUSPICIOUS_THRESHOLD']:
                status = 'suspicious'
                severity = 'medium'
            else:
                status = 'attack'
                severity = 'high' if attack_probability < 0.9 else 'critical'
            
            # Determinar tipo de ataque
            attack_type = self._determine_attack_type(flow, features)
            
            # Actualizar estadísticas
            self.stats[f'detections_{status}'] += 1
            self.stats['flows_analyzed'] += 1
            
            # Crear registro de detección
            detection = {
                'detection_id': str(uuid.uuid4()),
                'client_id': self.client_id,
                'timestamp': datetime.now(),
                'source_ip': flow.src_ip,
                'destination_ip': flow.dst_ip,
                'source_port': flow.src_port,
                'destination_port': flow.dst_port,
                'protocol': flow.protocol,
                'anomaly_type': attack_type if status == 'attack' else None,
                'severity': severity,
                'confidence_score': attack_probability,
                'raw_data': json.dumps({
                    'features': features,
                    'flow_stats': {
                        'packets': len(flow.packets),
                        'duration': flow.flow_duration,
                        'bytes': sum(flow.packet_sizes) if flow.packet_sizes else 0
                    }
                })
            }
            
            # Agregar a cola para BD
            self.detection_queue.append(detection)
            
            # Log de la detección
            self._log_detection(flow, status, attack_probability, attack_type)
            
        except Exception as e:
            logger.error(f"Error evaluando flujo: {e}")
    
    def _determine_attack_type(self, flow, features):
        """Determina el tipo de ataque basado en características"""
        try:
            # Port scan
            if features.get('unique_ports', 0) > 10 and features.get('packets_per_second', 0) > 5:
                return 'Port Scan'
            
            # DDoS/flooding
            if features.get('packets_per_second', 0) > 100:
                return 'DDoS'
            
            # Brute force (muchas conexiones cortas)
            if features.get('flow_duration', 0) < 1 and features.get('packet_count', 0) < 5:
                return 'Brute Force'
            
            # Web attacks (HTTP en puertos no estándar)
            if features.get('http_methods_count', 0) > 0 and flow.dst_port not in [80, 443, 8080]:
                return 'Web Attack'
            
            # DNS tunneling
            if features.get('dns_queries_count', 0) > 10:
                return 'DNS Tunneling'
            
            # Scanning (muchos RST/SYN)
            if features.get('rst_ratio', 0) > 0.5 or features.get('syn_ratio', 0) > 0.8:
                return 'Network Scan'
            
            return 'Unknown'
            
        except Exception as e:
            logger.error(f"Error determinando tipo de ataque: {e}")
            return 'Unknown'
    
    def _log_detection(self, flow, status, probability, attack_type):
        """Registra la detección en logs"""
        color = CONFIG['COLORS']['RED'] if status == 'attack' else \
                CONFIG['COLORS']['YELLOW'] if status == 'suspicious' else \
                CONFIG['COLORS']['GREEN']
        reset = CONFIG['COLORS']['RESET']
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        message = (f"{color}[{timestamp}] {status.upper()}: "
                  f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                  f"({flow.protocol}) Score: {probability:.4f}")
        
        if attack_type and attack_type != 'Unknown':
            message += f" Type: {attack_type}"
        
        message += reset
        
        if status != 'normal' or CONFIG['SHOW_NORMAL_TRAFFIC']:
            print(message)
        
        # Log a archivo
        if status == 'attack':
            logger.warning(f"ATTACK: {flow.src_ip}:{flow.src_port} -> "
                          f"{flow.dst_ip}:{flow.dst_port} ({attack_type}) "
                          f"Score: {probability:.4f}")
        elif status == 'suspicious':
            logger.info(f"SUSPICIOUS: {flow.src_ip}:{flow.src_port} -> "
                       f"{flow.dst_ip}:{flow.dst_port} Score: {probability:.4f}")
    
    def _database_worker(self):
        """Hilo para guardar detecciones en BD"""
        while self.running:
            try:
                time.sleep(2)  # Procesar cada 2 segundos
                
                # Recopilar detecciones en lotes
                batch = []
                while len(batch) < CONFIG['DB_BATCH_SIZE'] and self.detection_queue:
                    batch.append(self.detection_queue.popleft())
                
                if batch:
                    self._save_detections_to_db(batch)
                    
            except Exception as e:
                logger.error(f"Error en hilo de BD: {e}")
                time.sleep(5)
    
    def _save_detections_to_db(self, detections):
        """Guarda detecciones en la base de datos"""
        conn = None
        try:
            conn = obtener_conexion()
            if not conn:
                # Si no hay conexión, devolver a la cola
                self.detection_queue.extendleft(reversed(detections))
                return
            
            with conn.cursor() as cursor:
                for detection in detections:
                    cursor.execute("""
                        INSERT INTO detections (
                            detection_id, client_id, timestamp, source_ip, destination_ip,
                            source_port, destination_port, protocol, anomaly_type,
                            severity, confidence_score, raw_data
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        detection['detection_id'],
                        detection['client_id'],
                        detection['timestamp'],
                        detection['source_ip'],
                        detection['destination_ip'],
                        detection['source_port'],
                        detection['destination_port'],
                        detection['protocol'],
                        detection['anomaly_type'],
                        detection['severity'],
                        detection['confidence_score'],
                        detection['raw_data']
                    ))
                
                conn.commit()
                logger.debug(f"💾 {len(detections)} detecciones guardadas en BD")
                
        except Exception as e:
            logger.error(f"Error guardando en BD: {e}")
            # Devolver detecciones a la cola para reintento
            self.detection_queue.extendleft(reversed(detections))
        finally:
            if conn:
                conn.close()
    
    def _flush_detections_to_db(self):
        """Guarda todas las detecciones pendientes"""
        if not self.detection_queue:
            return
        
        remaining_detections = list(self.detection_queue)
        self.detection_queue.clear()
        
        logger.info(f"💾 Guardando {len(remaining_detections)} detecciones pendientes...")
        
        # Procesar en lotes
        for i in range(0, len(remaining_detections), CONFIG['DB_BATCH_SIZE']):
            batch = remaining_detections[i:i + CONFIG['DB_BATCH_SIZE']]
            self._save_detections_to_db(batch)
    
    def _stats_worker(self):
        """Hilo para mostrar estadísticas"""
        while self.running:
            try:
                time.sleep(CONFIG['UPDATE_INTERVAL'])
                self._print_stats()
            except Exception as e:
                logger.error(f"Error en estadísticas: {e}")
                time.sleep(CONFIG['UPDATE_INTERVAL'])
    
    def _print_stats(self):
        """Imprime estadísticas del detector"""
        runtime = time.time() - self.stats['start_time']
        
        with self.flow_lock:
            active_flows = len(self.flows)
        
        packets_per_sec = self.stats['packets_processed'] / max(runtime, 1)
        flows_per_sec = self.stats['flows_analyzed'] / max(runtime, 1)
        
        print(f"\n📊 ESTADÍSTICAS - {datetime.now().strftime('%H:%M:%S')}")
        print(f"⏱️  Runtime: {runtime:.0f}s")
        print(f"📦 Paquetes: {self.stats['packets_processed']:,} ({packets_per_sec:.1f}/s)")
        print(f"🌊 Flujos: activos={active_flows}, analizados={self.stats['flows_analyzed']:,} ({flows_per_sec:.3f}/s)")
        print(f"🔍 Detecciones: Normal={self.stats['detections_normal']:,}, "
              f"Sospechoso={self.stats['detections_suspicious']:,}, "
              f"Ataque={self.stats['detections_attack']:,}")
        print(f"🗄️  Cola BD: {len(self.detection_queue)} pendientes")
        print("-" * 80)
    
    def get_stats(self):
        """Obtiene estadísticas para API"""
        runtime = time.time() - self.stats['start_time']
        
        with self.flow_lock:
            active_flows = len(self.flows)
        
        return {
            'runtime': runtime,
            'packets_processed': self.stats['packets_processed'],
            'flows_analyzed': self.stats['flows_analyzed'],
            'active_flows': active_flows,
            'detections': {
                'normal': self.stats['detections_normal'],
                'suspicious': self.stats['detections_suspicious'],
                'attack': self.stats['detections_attack']
            },
            'rates': {
                'packets_per_second': self.stats['packets_processed'] / max(runtime, 1),
                'flows_per_second': self.stats['flows_analyzed'] / max(runtime, 1)
            },
            'queue_size': len(self.detection_queue)
        }

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Detector Integrado IDS")
    parser.add_argument("--model", default="model/modelo_rf.pkl", help="Ruta del modelo ML")
    parser.add_argument("--interface", default="Wi-Fi", help="Interfaz de red")
    parser.add_argument("--client-id", type=int, default=1, help="ID del cliente en BD")
    parser.add_argument("--normal-threshold", type=float, default=0.3, help="Umbral normal")
    parser.add_argument("--suspicious-threshold", type=float, default=0.7, help="Umbral sospechoso")
    parser.add_argument("--show-normal", action="store_true", help="Mostrar tráfico normal")
    
    args = parser.parse_args()
    
    # Actualizar configuración
    CONFIG['NORMAL_THRESHOLD'] = args.normal_threshold
    CONFIG['SUSPICIOUS_THRESHOLD'] = args.suspicious_threshold
    CONFIG['SHOW_NORMAL_TRAFFIC'] = args.show_normal
    
    print("🛡️  DETECTOR INTEGRADO IDS")
    print(f"🤖 Modelo: {args.model}")
    print(f"🌐 Interfaz: {args.interface}")
    print(f"🆔 Cliente ID: {args.client_id}")
    print(f"⚙️  Umbrales: Normal={args.normal_threshold}, Sospechoso={args.suspicious_threshold}")
    print("-" * 80)
    
    # Crear detector
    detector = DetectorIntegrado(args.model, args.interface, args.client_id)
    
    try:
        # Iniciar detección
        detector.start_detection()
        
        print("✅ Detector iniciado - Presiona Ctrl+C para detener")
        
        # Ejecutar hasta interrupción
        while detector.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Deteniendo detector...")
        detector.stop_detection()
        print("✅ Detector detenido")
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        detector.stop_detection()

if __name__ == "__main__":
    main()