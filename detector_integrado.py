#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detector Integrado con Base de Datos
-----------------------------------
Toma el detector.py existente e integra con BD PostgreSQL
"""

import sys
import os
import json
import uuid
import threading
import time
from datetime import datetime

# Importar el detector original
from detector import NetworkMonitor, CONFIG, logger, run_system

# Importar conexión BD
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor

class DetectorIntegradoBD(NetworkMonitor):
    """Extiende NetworkMonitor para integrar con base de datos"""
    
    def __init__(self, model_path, interface='Ethernet', client_id=1):
        super().__init__(model_path, interface)
        self.client_id = client_id
        
        # Cola para detecciones a guardar en BD
        self.detection_queue = []
        self.queue_lock = threading.Lock()
        
        # Hilo para guardar en BD
        self.db_thread = None
        self.db_stop_event = threading.Event()
        
        # Configurar cliente en BD
        self.setup_client_in_db()
    
    def setup_client_in_db(self):
        """Configura o actualiza el cliente en la base de datos"""
        try:
            conn = obtener_conexion()
            if not conn:
                logger.warning("No se pudo conectar a BD para configurar cliente")
                return
            
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Verificar si el cliente existe
                cursor.execute("""
                    SELECT id FROM federated_clients WHERE id = %s
                """, (self.client_id,))
                
                if cursor.fetchone():
                    # Actualizar cliente existente
                    cursor.execute("""
                        UPDATE federated_clients 
                        SET status = 'active', 
                            last_seen = CURRENT_TIMESTAMP,
                            description = 'Detector local integrado'
                        WHERE id = %s
                    """, (self.client_id,))
                    logger.info(f"Cliente {self.client_id} actualizado en BD")
                else:
                    # Crear nuevo cliente
                    cursor.execute("""
                        INSERT INTO federated_clients 
                        (id, name, description, ip_address, location, status, 
                         api_key, model_version, created_at, last_seen)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        self.client_id,
                        f'Detector-Local-{self.client_id}',
                        'Detector local integrado con BD',
                        '192.168.18.14',  # Tu IP local
                        'PC Principal - Detector Local',
                        'active',
                        f'local_key_{self.client_id}_{int(time.time())}',
                        'v1.0',
                        datetime.now(),
                        datetime.now()
                    ))
                    logger.info(f"Cliente {self.client_id} creado en BD")
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error configurando cliente en BD: {e}")
        finally:
            if conn:
                conn.close()
    
    def start_capture(self):
        """Inicia captura y también el hilo de BD"""
        # Iniciar hilo de base de datos
        self.db_stop_event.clear()
        self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self.db_thread.start()
        
        # Llamar al método padre
        super().start_capture()
    
    def stop_capture_threads(self):
        """Detiene todos los hilos incluyendo BD"""
        # Detener hilo de BD
        self.db_stop_event.set()
        if self.db_thread:
            self.db_thread.join(timeout=2.0)
        
        # Guardar detecciones pendientes
        self._flush_detection_queue()
        
        # Llamar al método padre
        super().stop_capture_threads()
    
    def _evaluate_flow(self, flow_id):
        """Sobrescribe la evaluación para guardar en BD"""
        try:
            start_time = time.time()
            flow = self.flows[flow_id]
            
            # Extraer características para el modelo
            features = flow.get_features()
            
            # Verificar si tenemos todas las características necesarias
            if not self.selected_features:
                feature_keys = sorted(features.keys())
                X = [features[f] for f in feature_keys]
                X = np.array([X])
                
                if self.scaler:
                    X_scaled = self.scaler.transform(X)
                else:
                    X_scaled = X
            else:
                missing_features = [f for f in self.selected_features if f not in features]
                if missing_features:
                    logger.debug(f"Características faltantes: {missing_features}")
                    return
                    
                X = [features[f] for f in self.selected_features]
                X = np.array([X])
                
                if self.scaler:
                    X_scaled = self.scaler.transform(X)
                else:
                    X_scaled = X
            
            # Evaluación híbrida de amenazas
            threat_result = self.threat_evaluator.evaluate_threat(flow, features, X_scaled)
            
            # Extraer resultados
            final_score = threat_result['score']
            ml_score = threat_result['ml_score']
            pattern_scores = threat_result['pattern_scores']
            primary_attack_type = threat_result['primary_attack_type']
            primary_attack_score = threat_result['primary_attack_score']
            status = threat_result['classification']
            
            # Actualizar contadores
            self.alert_counts[status] += 1
            self.performance_metrics['flows_analyzed'] += 1
            
            # Determinar tipo de ataque y severidad
            if status == 'attack':
                attack_type = primary_attack_type
                if final_score >= 0.9:
                    severity = 'critical'
                elif final_score >= 0.8:
                    severity = 'high'
                else:
                    severity = 'medium'
                    
                if attack_type not in self.attack_types:
                    attack_type = 'other'
                self.attack_types[attack_type] += 1
            elif status == 'suspicious':
                attack_type = None
                severity = 'medium'
            else:
                attack_type = None
                severity = 'low'
            
            # Crear registro de detección para BD
            detection_record = {
                'detection_id': str(uuid.uuid4()),
                'client_id': self.client_id,
                'timestamp': datetime.now(),
                'source_ip': flow.src_ip,
                'destination_ip': flow.dst_ip,
                'source_port': str(flow.src_port),
                'destination_port': str(flow.dst_port),
                'protocol': flow.protocol,
                'anomaly_type': attack_type,
                'severity': severity,
                'confidence_score': final_score,
                'raw_data': json.dumps({
                    'ml_score': ml_score,
                    'pattern_scores': dict(pattern_scores),
                    'features': {k: float(v) if isinstance(v, (int, float)) else v 
                               for k, v in features.items()},
                    'flow_stats': {
                        'packets': len(flow.packets),
                        'duration': flow.flow_duration,
                        'bytes': sum(flow.packet_lengths) if flow.packet_lengths else 0
                    }
                }),
                'is_confirmed': None,
                'false_positive': False
            }
            
            # Agregar a cola para BD
            with self.queue_lock:
                self.detection_queue.append(detection_record)
            
            # Log y print (código original)
            if status == 'normal':
                level = 'info'
            elif status == 'suspicious':
                level = 'warning'
            else:
                level = 'error'
            
            msg = f"[{status.upper()}] {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} ({flow.protocol}) - Prob: {final_score:.4f}"
            
            if status == 'attack':
                msg += f" - Tipo: {attack_type.upper()}"
            
            getattr(logger, level)(msg)
            
            if status != 'normal' or CONFIG['SHOW_NORMAL_TRAFFIC']:
                self._print_detection(status, flow, final_score, attack_type, pattern_scores)
            
            # Guardar detección para visualización
            detection_display = {
                'timestamp': datetime.now(),
                'flow_id': flow_id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'status': status,
                'score': final_score,
                'ml_score': ml_score,
                'attack_type': attack_type,
                'pattern_scores': pattern_scores,
                'packet_count': len(flow.packets),
                'duration': flow.flow_duration
            }
            
            self.recent_detections.append(detection_display)
            
            # Si es un ataque de alta confianza, eliminar flujo
            if status == 'attack' and final_score > 0.9:
                del self.flows[flow_id]
            
            # Registrar tiempo de detección
            detection_time = time.time() - start_time
            self.performance_metrics['detection_times'].append(detection_time)
            
        except Exception as e:
            logger.error(f"Error evaluando flujo {flow_id}: {str(e)}")
    
    def _db_worker(self):
        """Hilo trabajador para guardar detecciones en BD"""
        while not self.db_stop_event.is_set():
            try:
                # Recopilar detecciones a procesar
                detections_to_save = []
                with self.queue_lock:
                    if self.detection_queue:
                        # Tomar hasta 10 detecciones por lote
                        detections_to_save = self.detection_queue[:10]
                        self.detection_queue = self.detection_queue[10:]
                
                # Guardar en BD si hay detecciones
                if detections_to_save:
                    self._save_detections_to_db(detections_to_save)
                
                # Esperar antes del siguiente ciclo
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error en hilo de BD: {e}")
                time.sleep(5)
    
    def _save_detections_to_db(self, detections):
        """Guarda un lote de detecciones en la base de datos"""
        conn = None
        try:
            conn = obtener_conexion()
            if not conn:
                # Si no hay conexión, devolver detecciones a la cola
                with self.queue_lock:
                    self.detection_queue = detections + self.detection_queue
                return
            
            with conn.cursor() as cursor:
                for detection in detections:
                    cursor.execute("""
                        INSERT INTO detections (
                            detection_id, client_id, timestamp, source_ip, destination_ip,
                            source_port, destination_port, protocol, anomaly_type,
                            severity, confidence_score, raw_data, is_confirmed, false_positive
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                        detection['raw_data'],
                        detection['is_confirmed'],
                        detection['false_positive']
                    ))
                
                conn.commit()
                logger.debug(f"💾 Guardadas {len(detections)} detecciones en BD")
                
        except Exception as e:
            logger.error(f"Error guardando detecciones en BD: {e}")
            # Devolver detecciones a la cola para reintento
            with self.queue_lock:
                self.detection_queue = detections + self.detection_queue
        finally:
            if conn:
                conn.close()
    
    def _flush_detection_queue(self):
        """Guarda todas las detecciones pendientes antes de cerrar"""
        with self.queue_lock:
            if self.detection_queue:
                logger.info(f"💾 Guardando {len(self.detection_queue)} detecciones pendientes...")
                self._save_detections_to_db(self.detection_queue)
                self.detection_queue.clear()

def run_detector_integrado(model_path, interface, client_id=1, duration=0):
    """Ejecuta el detector integrado con BD"""
    try:
        # Importar numpy aquí para evitar conflictos
        import numpy as np
        globals()['np'] = np
        
        # Crear detector integrado
        detector = DetectorIntegradoBD(model_path, interface, client_id)
        
        # Mostrar información inicial
        print(f"🛡️  DETECTOR INTEGRADO CON BASE DE DATOS")
        print(f"📊 Cliente ID: {client_id}")
        print(f"🌐 Interfaz: {interface}")
        print(f"🤖 Modelo: {model_path}")
        print(f"🔗 Enviando detecciones a BD en tiempo real")
        print("-" * 60)
        
        # Iniciar captura
        detector.start_capture()
        
        # Ejecutar por duración especificada o hasta interrupción
        if duration > 0:
            time.sleep(duration)
            detector.stop_capture_threads()
        else:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Deteniendo detector...")
                detector.stop_capture_threads()
        
        print("✅ Detector detenido")
        
    except Exception as e:
        logger.error(f"Error ejecutando detector integrado: {e}")
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Detector Integrado con Base de Datos")
    parser.add_argument("--model", default="model/modelo_rf.pkl", help="Ruta del modelo ML")
    parser.add_argument("--interface", default="Ethernet", help="Interfaz de red")
    parser.add_argument("--client-id", type=int, default=1, help="ID del cliente en BD")
    parser.add_argument("--duration", type=int, default=0, help="Duración en segundos (0=indefinido)")
    
    args = parser.parse_args()
    
    run_detector_integrado(args.model, args.interface, args.client_id, args.duration)