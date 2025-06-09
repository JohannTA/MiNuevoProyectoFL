#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Detección de Intrusiones en Tiempo Real (Versión Mejorada)
--------------------------------------------------------------------
Este sistema captura tráfico de red, extrae características de flujos y utiliza
un modelo de aprendizaje automático para detectar intrusiones en tiempo real
con capacidades mejoradas para detectar escaneos de puertos y ataques web.

Autor: [Tu Nombre]
Fecha: 2025-06-03
Versión: 2.0
"""

import os
import time
import pickle
import joblib
import numpy as np
import pandas as pd
import pyshark
import argparse
import socket
import threading
import datetime
import logging
import hashlib
import ipaddress
from collections import defaultdict, deque, Counter
from sklearn.preprocessing import StandardScaler
import warnings
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ignorar advertencias
warnings.filterwarnings("ignore")

# Configuración global
CONFIG = {
    # Umbrales de detección más precisos
    'NORMAL_THRESHOLD': 0.05,     # Probabilidad < 0.05: normal
    'SUSPICIOUS_THRESHOLD': 0.15, # 0.05 <= Probabilidad < 0.15: sospechoso
                                  # Probabilidad >= 0.15: ataque
    
    # Parámetros para detección de escaneo de puertos
    'PORT_SCAN_THRESHOLD': 5,     # Número de puertos diferentes para considerar escaneo
    'PORT_SCAN_TIME_WINDOW': 10,  # Ventana de tiempo para escaneo (segundos)
    
    # Parámetros para detección de ataques web
    'WEB_PORTS': [80, 443, 8080, 8443, 3000, 4200, 5000, 8000],  # Puertos web comunes
    
    # Límites de frecuencia para detección basada en umbral
    'MAX_CONN_PER_SEC': 20,       # Conexiones por segundo (TCP)
    'MAX_PACKETS_PER_SEC': 100,   # Paquetes por segundo
    'SYN_RATIO_THRESHOLD': 0.8,   # Ratio de paquetes SYN para considerar ataque
    
    # Parámetros para detección de anomalías
    'ENTROPY_THRESHOLD': 0.8,     # Umbral de entropía para comportamiento anómalo
}

class EnhancedFlowRecord:
    """Clase mejorada para almacenar y analizar información de flujos de red"""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Identificación de flujo
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Almacenamiento de paquetes y tiempos
        self.packets = []
        self.start_time = None
        self.last_update = time.time()
        self.creation_time = time.time()
        
        # Estadísticas de flujo direccional
        self.fwd_packets = []  # Paquetes de origen a destino
        self.bwd_packets = []  # Paquetes de destino a origen
        
        # Métricas de tamaño y tiempo
        self.packet_lengths = []
        self.packet_times = []
        self.last_packet_time = None
        self.flow_duration = 0
        self.inter_arrival_times = []
        self.fwd_inter_arrival_times = []
        self.bwd_inter_arrival_times = []
        
        # Banderas TCP
        self.flags = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 
            'PSH': 0, 'ACK': 0, 'URG': 0
        }
        
        # NUEVAS CARACTERÍSTICAS MEJORADAS
        # ---------------------------------
        
        # Para detección de escaneo de puertos
        self.is_scan_suspect = False
        self.port_variety = 1
        self.connection_attempts = 0
        self.failed_connections = 0
        
        # Para detección de ataques web
        self.http_methods = Counter()
        self.http_status_codes = Counter()
        self.http_payloads = []
        self.web_traffic = False
        
        # Para análisis de carga útil
        self.payload_sizes = []
        self.payload_entropy = 0
        self.avg_payload_size = 0
        
        # Para análisis de conexiones
        self.connection_state = "UNKNOWN"
        self.retransmissions = 0
        self.out_of_order = 0
        self.packet_rate = 0
        self.byte_rate = 0
        self.syn_fin_ratio = 0
        
        # Ventanas temporales para tasas
        self.time_windows = defaultdict(list)
        self.window_size = 1  # 1 segundo
        
        # Historial de puertos vistos
        self.ports_seen = set()
        
        # Detección de comportamiento periódico
        self.periodic_behavior = 0
        self.packet_intervals = []
    
    def add_packet(self, packet, timestamp):
        """Añade un paquete al flujo y actualiza estadísticas con análisis mejorado"""
        # Inicializar tiempo de inicio si es el primer paquete
        if not self.start_time:
            self.start_time = timestamp
        
        # Calcular tiempos entre llegadas
        if self.last_packet_time:
            iat = timestamp - self.last_packet_time
            self.inter_arrival_times.append(iat)
            
            # Análisis de periodicidad (útil para detectar beacons de malware)
            if len(self.inter_arrival_times) > 5:
                iat_std = np.std(self.inter_arrival_times[-5:])
                iat_mean = np.mean(self.inter_arrival_times[-5:])
                if iat_std < 0.1 * iat_mean:  # Baja variación indica comportamiento periódico
                    self.periodic_behavior += 1
        
        self.last_packet_time = timestamp
        self.flow_duration = timestamp - self.start_time
        self.last_update = time.time()
        
        # Registrar tiempo y guardar paquete
        self.packet_times.append(timestamp)
        self.packets.append(packet)
        
        # Extraer información del paquete
        try:
            # Procesamiento básico
            packet_len = int(packet.length)
            self.packet_lengths.append(packet_len)
            
            # Determinar dirección del paquete
            is_forward = False
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                is_forward = (src_ip == self.src_ip and dst_ip == self.dst_ip)
            
            # Actualizar métricas de dirección
            if is_forward:
                self.fwd_packets.append(packet_len)
                if len(self.fwd_packets) > 1 and len(self.inter_arrival_times) > 0:
                    self.fwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            else:
                self.bwd_packets.append(packet_len)
                if len(self.bwd_packets) > 1 and len(self.inter_arrival_times) > 0:
                    self.bwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            
            # Procesamiento específico por protocolo
            if hasattr(packet, 'tcp'):
                # Procesar banderas TCP
                for flag in self.flags:
                    if hasattr(packet.tcp, flag.lower()) and int(getattr(packet.tcp, flag.lower())) == 1:
                        self.flags[flag] += 1
                
                # Analizar estado de conexión
                if self.flags['SYN'] > 0 and self.flags['ACK'] == 0:
                    self.connection_state = "SYN_SENT"
                    self.connection_attempts += 1
                elif self.flags['SYN'] > 0 and self.flags['ACK'] > 0:
                    self.connection_state = "ESTABLISHED"
                elif self.flags['FIN'] > 0:
                    self.connection_state = "FIN_WAIT"
                elif self.flags['RST'] > 0:
                    self.connection_state = "CLOSED"
                    self.failed_connections += 1
                
                # Detectar posibles retransmisiones
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    self.retransmissions += 1
                
                # Detectar paquetes fuera de orden
                if hasattr(packet.tcp, 'analysis_out_of_order'):
                    self.out_of_order += 1
                
                # Guardar puerto destino para análisis de escaneo
                if hasattr(packet.tcp, 'dstport'):
                    self.ports_seen.add(int(packet.tcp.dstport))
                
                # Detección de tráfico web
                if int(packet.tcp.srcport) in CONFIG['WEB_PORTS'] or int(packet.tcp.dstport) in CONFIG['WEB_PORTS']:
                    self.web_traffic = True
                    # Si hay payload HTTP, extraer información
                    if hasattr(packet, 'http'):
                        if hasattr(packet.http, 'request_method'):
                            self.http_methods[packet.http.request_method] += 1
                        if hasattr(packet.http, 'response_code'):
                            self.http_status_codes[packet.http.response_code] += 1
                        # Análisis básico de payload
                        if hasattr(packet.http, 'file_data'):
                            self.http_payloads.append(packet.http.file_data)
                            
                            # Calcular entropía del payload para detectar cifrado/ofuscación
                            entropy = self._calculate_entropy(packet.http.file_data)
                            self.payload_entropy = max(self.payload_entropy, entropy)
            
            # Actualizar tasa de paquetes por segundo
            window_index = int(timestamp - self.start_time)
            self.time_windows[window_index].append(packet_len)
            
            # Actualizar estadísticas de escaneo
            if len(self.ports_seen) >= CONFIG['PORT_SCAN_THRESHOLD']:
                if self.flow_duration <= CONFIG['PORT_SCAN_TIME_WINDOW']:
                    self.is_scan_suspect = True
        
        except Exception as e:
            logger.warning(f"Error procesando paquete: {e}")
    
    def _calculate_entropy(self, data):
        """Calcula la entropía de Shannon de los datos"""
        if not data:
            return 0
            
        try:
            # Convertir a bytes si es string
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Frecuencia de bytes
            freq = Counter(data)
            data_len = len(data)
            
            # Calcular entropía
            entropy = 0
            for count in freq.values():
                prob = count / data_len
                entropy -= prob * np.log2(prob)
            
            # Normalizar (0-1)
            return entropy / 8.0  # 8 bits máximo por byte
        except:
            return 0
    
    def get_features(self):
        """Extrae características del flujo compatibles con el modelo entrenado"""
        
        # Evitar divisiones por cero
        n_packets = max(1, len(self.packets))
        fwd_packets = max(1, len(self.fwd_packets))
        bwd_packets = max(1, len(self.bwd_packets))
        flow_duration = max(0.001, self.flow_duration)
        
        # Características básicas de flujo
        total_fwd_packets = len(self.fwd_packets)
        total_bwd_packets = len(self.bwd_packets)
        
        # Longitudes de paquetes
        total_fwd_length = sum(self.fwd_packets)
        total_bwd_length = sum(self.bwd_packets)
        
        # Estadísticas de tamaño de paquetes
        if self.packet_lengths:
            packet_length_mean = np.mean(self.packet_lengths)
            packet_length_std = np.std(self.packet_lengths) if len(self.packet_lengths) > 1 else 0
            packet_length_variance = np.var(self.packet_lengths) if len(self.packet_lengths) > 1 else 0
            min_packet_length = min(self.packet_lengths)
            max_packet_length = max(self.packet_lengths)
        else:
            packet_length_mean = packet_length_std = packet_length_variance = min_packet_length = max_packet_length = 0
        
        # Promedios de segmentos
        avg_fwd_segment_size = np.mean(self.fwd_packets) if self.fwd_packets else 0
        avg_bwd_segment_size = np.mean(self.bwd_packets) if self.bwd_packets else 0
        
        # Tasas de flujo
        flow_bytes_per_sec = (total_fwd_length + total_bwd_length) / flow_duration
        flow_packets_per_sec = n_packets / flow_duration
        
        # Tiempos entre llegadas (IAT)
        if self.inter_arrival_times:
            flow_iat_mean = np.mean(self.inter_arrival_times)
            flow_iat_std = np.std(self.inter_arrival_times) if len(self.inter_arrival_times) > 1 else 0
        else:
            flow_iat_mean = flow_iat_std = 0
        
        if self.fwd_inter_arrival_times:
            fwd_iat_mean = np.mean(self.fwd_inter_arrival_times)
        else:
            fwd_iat_mean = 0
        
        if self.bwd_inter_arrival_times:
            bwd_iat_mean = np.mean(self.bwd_inter_arrival_times)
        else:
            bwd_iat_mean = 0
        
        # Subflujos
        subflow_fwd_packets = total_fwd_packets  # Simplificación
        subflow_fwd_bytes = total_fwd_length     # Simplificación
        subflow_bwd_packets = total_bwd_packets  # Simplificación
        subflow_bwd_bytes = total_bwd_length     # Simplificación
        
        # Crear diccionario de características
        features = {
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_backward_packets': total_bwd_packets,
            'total_length_of_fwd_packets': total_fwd_length,
            'total_length_of_bwd_packets': total_bwd_length,
            'flow_bytes/s': flow_bytes_per_sec,
            'flow_packets/s': flow_packets_per_sec,
            'flow_iat_mean': flow_iat_mean,
            'flow_iat_std': flow_iat_std,
            'fwd_iat_mean': fwd_iat_mean,
            'bwd_iat_mean': bwd_iat_mean,
            'fin_flag_count': self.flags['FIN'],
            'syn_flag_count': self.flags['SYN'],
            'rst_flag_count': self.flags['RST'],
            'psh_flag_count': self.flags['PSH'],
            'ack_flag_count': self.flags['ACK'],
            'packet_length_mean': packet_length_mean,
            'packet_length_std': packet_length_std,
            'packet_length_variance': packet_length_variance,
            'avg_fwd_segment_size': avg_fwd_segment_size,
            'avg_bwd_segment_size': avg_bwd_segment_size,
            'subflow_fwd_packets': subflow_fwd_packets,
            'subflow_fwd_bytes': subflow_fwd_bytes,
            'subflow_bwd_packets': subflow_bwd_packets,
            'subflow_bwd_bytes': subflow_bwd_bytes
        }
        
        return features
    
    def calculate_scan_score(self):
        """Calcula puntaje de probabilidad de escaneo de puertos"""
        score = 0.0
        
        # Factor 1: Número de puertos distintos vistos
        port_factor = min(len(self.ports_seen) / CONFIG['PORT_SCAN_THRESHOLD'], 1.0) * 0.4
        score += port_factor
        
        # Factor 2: Ratio de SYN a ACK (muchos SYN sin ACK indican escaneo)
        if self.flags['SYN'] > 0:
            syn_ack_ratio = 1.0 - (min(self.flags['ACK'], self.flags['SYN']) / self.flags['SYN'])
            score += syn_ack_ratio * 0.3
        
        # Factor 3: Tasa de conexiones fallidas (RST)
        if self.connection_attempts > 0:
            failure_ratio = min(self.failed_connections / self.connection_attempts, 1.0) * 0.3
            score += failure_ratio
        
        # Factor 4: Baja duración de flujo con muchos intentos
        if self.flow_duration < 5.0 and len(self.ports_seen) > 3:
            score += 0.2
            
        # Factor 5: Período muy corto entre paquetes
        if self.inter_arrival_times and np.mean(self.inter_arrival_times) < 0.1:
            score += 0.1
        
        return min(score, 1.0)  # Normalizar a escala 0-1
    
    def calculate_web_attack_score(self):
        """Calcula puntaje de probabilidad de ataque web"""
        score = 0.0
        
        if not self.web_traffic:
            return 0.0
        
        # Factor 1: Solicitudes HTTP con patrones sospechosos
        suspicious_methods = {'OPTIONS', 'TRACE', 'CONNECT', 'DELETE', 'PUT'}
        for method in suspicious_methods:
            if method in self.http_methods:
                score += 0.2
                
        # Factor 2: Entropía alta en payload (posible ofuscación)
        if self.payload_entropy > CONFIG['ENTROPY_THRESHOLD']:
            score += 0.3
            
        # Factor 3: Errores HTTP o respuestas sospechosas
        error_codes = {'400', '401', '403', '500', '501', '502', '503'}
        for code in error_codes:
            if code in self.http_status_codes:
                score += 0.15
        
        # Factor 4: Payload con patrones típicos de ataques
        suspicious_patterns = [
            "script", "alert(", "SELECT", "UNION", "INSERT", "UPDATE", 
            "DELETE FROM", "DROP TABLE", "<script>", "eval(", "exec(",
            "system(", "cmd.exe", "powershell", "bash", "/etc/passwd",
            "admin' --", "' OR 1=1", "../../", ".htaccess"
        ]
        
        for payload in self.http_payloads:
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', 'ignore').lower()
            else:
                payload_str = str(payload).lower()
            
            for pattern in suspicious_patterns:
                if pattern.lower() in payload_str:
                    score += 0.25
                    break
        
        return min(score, 1.0)  # Normalizar a escala 0-1
    
    def calculate_dos_score(self):
        """Calcula puntaje de probabilidad de ataque DoS"""
        score = 0.0
        
        # Factor 1: Tasa alta de paquetes por segundo
        packets_per_sec = len(self.packet_lengths) / max(0.1, self.flow_duration)
        if packets_per_sec > CONFIG['MAX_PACKETS_PER_SEC']:
            score += min(packets_per_sec / CONFIG['MAX_PACKETS_PER_SEC'], 5.0) * 0.2
        
        # Factor 2: Tasa alta de SYN sin ACK (SYN flood)
        if self.flags['SYN'] > 10 and self.flags['SYN'] > self.flags['ACK'] * 2:
            score += 0.4
        
        # Factor 3: Muchas retransmisiones (indicativo de saturación)
        if self.retransmissions > 5:
            score += min(self.retransmissions / 20.0, 1.0) * 0.2
        
        # Factor 4: Muchos paquetes pequeños (amplificación)
        if self.packet_lengths and np.mean(self.packet_lengths) < 100 and len(self.packet_lengths) > 50:
            score += 0.2
            
        # Factor 5: Tamaños de paquete consistentes (comportamiento automatizado)
        if self.packet_lengths and np.std(self.packet_lengths) < 5 and len(self.packet_lengths) > 10:
            score += 0.2
        
        return min(score, 1.0)  # Normalizar a escala 0-1


class EnhancedNetworkMonitor:
    """Clase mejorada para monitoreo de red e identificación de intrusiones"""
    
    def __init__(self, model_path, interface='eth0', timeout=60):
        """
        Inicializa el monitor de red con capacidades avanzadas
        
        Args:
            model_path: Ruta al modelo entrenado
            interface: Interfaz de red a monitorear
            timeout: Tiempo de espera para considerar un flujo como finalizado
        """
        self.model_path = model_path
        self.interface = interface
        self.timeout = timeout
        self.flows = {}  # Diccionario para almacenar flujos activos
        self.flow_lock = threading.Lock()
        self.stop_capture = threading.Event()
        self.capture_thread = None
        self.cleanup_thread = None
        
        # Carga del modelo y componentes de preprocesamiento
        try:
            logger.info(f"Cargando modelo desde {model_path}")
            model_data = joblib.load(model_path)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.selected_features = model_data['selected_features']
            
            logger.info("Modelo cargado exitosamente")
            logger.info(f"Características requeridas: {self.selected_features}")
        except Exception as e:
            logger.error(f"Error cargando el modelo: {e}")
            raise
        
        # Contadores de alertas
        self.alert_counts = {
            'normal': 0,
            'suspicious': 0,
            'attack': 0
        }
        
        # Desglose por tipo de ataque
        self.attack_types = {
            'scan': 0,
            'dos': 0,
            'web': 0,
            'brute': 0,
            'other': 0
        }
        
        # Cola para registro de detecciones recientes
        self.recent_detections = deque(maxlen=200)
        
        # Umbrales de clasificación (más sensibles basados en los resultados observados)
        self.thresholds = {
            'normal': CONFIG['NORMAL_THRESHOLD'],
            'suspicious': CONFIG['SUSPICIOUS_THRESHOLD']
        }
        
        # Sistema de tracking de conexiones para correlacionar eventos
        self.connection_tracker = defaultdict(lambda: {
            'ports': set(),
            'last_update': time.time(),
            'connections': 0,
            'failed': 0,
            'scan_score': 0
        })
        
        # Sistema para detección de comportamiento de red anómalo
        self.network_baseline = {
            'avg_flows_per_min': 0,
            'avg_packets_per_flow': 0,
            'last_update': time.time(),
            'history': []
        }
        
        # Sistema de reputación de IPs
        self.ip_reputation = {}
        self.load_ip_reputation()
        
        # Iniciar generación del baseline
        self.baseline_thread = threading.Thread(target=self._update_baseline)
        self.baseline_thread.daemon = True
        self.baseline_thread.start()
    
    def load_ip_reputation(self):
        """Carga base de datos de reputación de IPs (placeholder)"""
        # En una implementación real, cargaría de una base de datos o servicio externo
        # Simulación simple:
        malicious_networks = [
            '185.156.73.0/24',  # Ejemplo - sustituir por redes reales
            '91.219.236.0/24',
            '185.183.107.0/24',
            '45.227.255.0/24'
        ]
        
        self.malicious_networks = []
        for network in malicious_networks:
            try:
                self.malicious_networks.append(ipaddress.ip_network(network))
            except:
                pass
    
    def check_ip_reputation(self, ip):
        """Verifica reputación de una IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Verificar si la IP está en alguna red maliciosa conocida
            for network in self.malicious_networks:
                if ip_obj in network:
                    return 0.8  # Alta probabilidad de malicioso
            
            # Si es una IP privada, es neutral
            if ip_obj.is_private:
                return 0.0
            
            # Si es una IP reservada o multicast, es neutral
            if ip_obj.is_reserved or ip_obj.is_multicast:
                return 0.0
                
            return 0.0  # Neutral por defecto
        except:
            return 0.0
    
    def _update_baseline(self):
        """Actualiza periódicamente la línea base de comportamiento normal"""
        while not self.stop_capture.is_set():
            try:
                # Cada 60 segundos, actualizar baseline
                time.sleep(60)
                
                with self.flow_lock:
                    # Calcular métricas de baseline
                    active_flows = len(self.flows)
                    total_packets = sum(len(flow.packets) for flow in self.flows.values())
                    avg_packets = total_packets / max(active_flows, 1)
                    
                    # Actualizar historial
                    self.network_baseline['history'].append({
                        'timestamp': time.time(),
                        'flows': active_flows,
                        'avg_packets': avg_packets
                    })
                    
                    # Limitar historial a últimas 24 horas
                    cutoff = time.time() - (24 * 3600)
                    self.network_baseline['history'] = [
                        entry for entry in self.network_baseline['history'] 
                        if entry['timestamp'] > cutoff
                    ]
                    
                    # Actualizar promedios
                    if self.network_baseline['history']:
                        self.network_baseline['avg_flows_per_min'] = np.mean(
                            [entry['flows'] for entry in self.network_baseline['history']]
                        )
                        self.network_baseline['avg_packets_per_flow'] = np.mean(
                            [entry['avg_packets'] for entry in self.network_baseline['history']]
                        )
                    
                    self.network_baseline['last_update'] = time.time()
                    
            except Exception as e:
                logger.error(f"Error actualizando baseline: {e}")
    
    def start_capture(self):
        """Inicia la captura de paquetes en un hilo separado"""
        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("La captura ya está en ejecución")
            return
        
        self.stop_capture.clear()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.cleanup_thread = threading.Thread(target=self._cleanup_flows)
        
        logger.info(f"Iniciando captura en la interfaz {self.interface}")
        self.capture_thread.start()
        self.cleanup_thread.start()
    
    def stop_capture_thread(self):
        """Detiene la captura de paquetes"""
        logger.info("Deteniendo captura de paquetes")
        self.stop_capture.set()
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)
    
    def _capture_packets(self):
        """Función para capturar paquetes y procesarlos"""
        try:
            # Configurar un nuevo event loop para este hilo
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Configurar captura
            capture = pyshark.LiveCapture(interface=self.interface)
            
            logger.info(f"Captura iniciada en {self.interface}")
            
            # Iniciar captura de paquetes
            for packet in capture.sniff_continuously():
                if self.stop_capture.is_set():
                    break
                
                try:
                    self._process_packet(packet)
                except Exception as e:
                    logger.error(f"Error procesando paquete: {e}")
            
        except Exception as e:
            logger.error(f"Error en la captura: {e}")
    
    def _process_packet(self, packet):
        """Procesa un paquete y lo añade al flujo correspondiente con análisis avanzado"""
        # Verificar si es un paquete IP
        if not hasattr(packet, 'ip'):
            return
        
        # Obtener información del paquete
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        # Valores por defecto
        src_port = dst_port = '0'
        protocol = packet.ip.proto
        
        # Obtener puertos si es TCP o UDP
        if hasattr(packet, 'tcp'):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol = 'TCP'
        elif hasattr(packet, 'udp'):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol = 'UDP'
        
        # Crear identificador único para el flujo
        # Normalizar dirección (siempre el menor IP/puerto primero)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            flow_direction = "forward"
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            flow_direction = "backward"
        
        # Actualizar el rastreador de conexiones para detección de escaneo
        if protocol == 'TCP':
            self._update_connection_tracker(src_ip, int(dst_port), packet)
        
        # Añadir paquete al flujo correspondiente
        with self.flow_lock:
            if flow_id not in self.flows:
                self.flows[flow_id] = EnhancedFlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
            
            timestamp = float(packet.sniff_timestamp)
            self.flows[flow_id].add_packet(packet, timestamp)
            
            # Si hay suficientes paquetes, evaluar el flujo
            if len(self.flows[flow_id].packets) >= 10:
                self._evaluate_flow(flow_id)
    
    def _update_connection_tracker(self, src_ip, dst_port, packet):
        """Actualiza el rastreador de conexiones para detección de escaneo"""
        if src_ip not in self.connection_tracker:
            self.connection_tracker[src_ip] = {
                'ports': set(),
                'last_update': time.time(),
                'connections': 0,
                'failed': 0,
                'scan_score': 0
            }
        
        # Añadir puerto a puertos visitados
        self.connection_tracker[src_ip]['ports'].add(dst_port)
        self.connection_tracker[src_ip]['last_update'] = time.time()
        
        # Contar intentos de conexión
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
            # SYN indica intento de conexión
            if hasattr(packet.tcp, 'flags_syn') and int(packet.tcp.flags_syn) == 1:
                self.connection_tracker[src_ip]['connections'] += 1
            
            # RST indica conexión fallida
            if hasattr(packet.tcp, 'flags_reset') and int(packet.tcp.flags_reset) == 1:
                self.connection_tracker[src_ip]['failed'] += 1
        
        # Calcular puntuación de escaneo
        port_count = len(self.connection_tracker[src_ip]['ports'])
        failed_ratio = 0
        
        if self.connection_tracker[src_ip]['connections'] > 0:
            failed_ratio = self.connection_tracker[src_ip]['failed'] / self.connection_tracker[src_ip]['connections']
        
        # Puntuación basada en número de puertos y ratio de fallos
        if port_count >= CONFIG['PORT_SCAN_THRESHOLD']:
            port_factor = min(port_count / 20, 1.0)
            time_factor = 1.0
            
            # Considerar tiempo: más puertos en menos tiempo = más sospechoso
            time_window = time.time() - self.connection_tracker[src_ip]['last_update'] + 1
            if time_window < CONFIG['PORT_SCAN_TIME_WINDOW']:
                time_factor = CONFIG['PORT_SCAN_TIME_WINDOW'] / time_window
            
            self.connection_tracker[src_ip]['scan_score'] = min(
                port_factor * 0.6 + failed_ratio * 0.3 + time_factor * 0.1, 
                1.0
            )
    
    def _cleanup_flows(self):
        """Limpia flujos inactivos periódicamente"""
        while not self.stop_capture.is_set():
            time.sleep(5)  # Verificar cada 5 segundos
            
            current_time = time.time()
            expired_flows = []
            
            with self.flow_lock:
                for flow_id, flow in self.flows.items():
                    # Si el flujo no se ha actualizado en timeout segundos
                    if current_time - flow.last_update > self.timeout:
                        expired_flows.append(flow_id)
                        
                        # Evaluar el flujo antes de eliminarlo si tiene suficientes paquetes
                        if len(flow.packets) >= 5:
                            self._evaluate_flow(flow_id)
                
                # Eliminar flujos expirados
                for flow_id in expired_flows:
                    del self.flows[flow_id]
            
            # Limpiar también el rastreador de conexiones
            expired_trackers = []
            for src_ip, data in self.connection_tracker.items():
                if current_time - data['last_update'] > self.timeout * 2:
                    expired_trackers.append(src_ip)
            
            for src_ip in expired_trackers:
                del self.connection_tracker[src_ip]
            
            if expired_flows:
                logger.debug(f"Se eliminaron {len(expired_flows)} flujos inactivos")
    
    def _evaluate_flow(self, flow_id):
        """Evalúa un flujo para detectar posibles intrusiones con análisis avanzado"""
        try:
            flow = self.flows[flow_id]
            
            # 1. Obtener características del flujo para el modelo
            features = flow.get_features()
            
            # Verificar que las características requeridas estén presentes
            missing_features = [f for f in self.selected_features if f not in features]
            if missing_features:
                logger.warning(f"Características faltantes: {missing_features}")
                return
            
            # 2. Preparar datos para el modelo
            X = [features[f] for f in self.selected_features]
            X = np.array([X])
            
            # 3. Aplicar escalado
            X_scaled = self.scaler.transform(X)
            
            # 4. Obtener predicción básica del modelo
            y_pred = self.model.predict(X_scaled)
            y_proba = self.model.predict_proba(X_scaled)[0, 1]  # Probabilidad de ataque
            
            # 5. ANÁLISIS AVANZADO: Integrar múltiples fuentes de decisión
            # ------------------------------------------------------------
            
            # 5.1. Analizar patrones de escaneo de puertos
            scan_score = flow.calculate_scan_score()
            
            # 5.2. Analizar posibles ataques web
            web_score = flow.calculate_web_attack_score()
            
            # 5.3. Analizar posibles ataques DoS
            dos_score = flow.calculate_dos_score()
            
            # 5.4. Verificar reputación de las IPs
            src_reputation = self.check_ip_reputation(flow.src_ip)
            dst_reputation = self.check_ip_reputation(flow.dst_ip)
            reputation_score = max(src_reputation, dst_reputation)
            
            # 5.5. Integrar todas las señales en una puntuación final
            # Dar más peso al modelo ML pero incrementar con otras señales
            enhanced_score = y_proba * 0.5  # Modelo ML: 50% del peso
            
            # Tipo-específico: tomar la mayor puntuación
            attack_type_score = max(scan_score, web_score, dos_score)
            attack_type = "other"
            
            if scan_score > web_score and scan_score > dos_score and scan_score > 0.6:
                attack_type = "scan"
            elif web_score > scan_score and web_score > dos_score and web_score > 0.6:
                attack_type = "web"
            elif dos_score > scan_score and dos_score > web_score and dos_score > 0.6:
                attack_type = "dos"
            
            # Combinar puntuaciones
            enhanced_score += attack_type_score * 0.3  # Ataques específicos: 30%
            enhanced_score += reputation_score * 0.2   # Reputación: 20%
            
            # Normalizar al rango [0,1]
            enhanced_score = min(enhanced_score, 1.0)
            
            # 6. Clasificar según umbrales mejorados
            if enhanced_score < self.thresholds['normal']:
                status = 'normal'
                level = 'info'
            elif enhanced_score < self.thresholds['suspicious']:
                status = 'suspicious'
                level = 'warning'
            else:
                status = 'attack'
                level = 'error'
                # Contar tipo de ataque
                self.attack_types[attack_type] += 1
            
            # 7. Actualizar contadores
            self.alert_counts[status] += 1
            
            # 8. Crear mensaje de detección con más detalles
            msg = (f"[{status.upper()}] "
                   f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} "
                   f"({flow.protocol}) - Prob: {enhanced_score:.4f}")
                   
            if status == 'attack':
                msg += f" - Tipo: {attack_type.upper()}"
                if attack_type == "scan":
                    msg += f" - Puertos: {len(flow.ports_seen)}"
                elif attack_type == "web":
                    msg += f" - Métodos: {dict(flow.http_methods)}"
            
            # 9. Registrar según nivel
            if level == 'info':
                logger.info(msg)
            elif level == 'warning':
                logger.warning(msg)
            else:
                logger.error(msg)
            
            # 10. Guardar detección para visualización
            detection_record = {
                'timestamp': datetime.datetime.now(),
                'flow_id': flow_id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'status': status,
                'attack_type': attack_type if status == 'attack' else None,
                'probability': enhanced_score,
                'model_prob': y_proba,
                'scan_score': scan_score,
                'web_score': web_score,
                'dos_score': dos_score,
                'packet_count': len(flow.packets),
                'flags': flow.flags.copy() if hasattr(flow, 'flags') else {},
                'ports_accessed': list(flow.ports_seen) if hasattr(flow, 'ports_seen') else []
            }
            
            self.recent_detections.append(detection_record)
            
            # 11. Eliminar el flujo evaluado si fue clasificado como ataque grave
            if status == 'attack' and enhanced_score > 0.8:
                del self.flows[flow_id]
        
        except Exception as e:
            logger.error(f"Error evaluando flujo {flow_id}: {e}")
    
    def get_stats(self):
        """Retorna estadísticas de detección ampliadas"""
        with self.flow_lock:
            flow_count = len(self.flows)
        
        # Estadísticas básicas
        stats = {
            'timestamp': datetime.datetime.now(),
            'active_flows': flow_count,
            'normal_count': self.alert_counts['normal'],
            'suspicious_count': self.alert_counts['suspicious'],
            'attack_count': self.alert_counts['attack'],
            'total_analyzed': sum(self.alert_counts.values()),
            'recent_detections': list(self.recent_detections)
        }
        
        # Añadir estadísticas por tipo de ataque
        stats['attack_types'] = {k: v for k, v in self.attack_types.items()}
        
        # Añadir estadísticas de las IPs más activas
        top_ips = Counter()
        suspicious_ips = Counter()
        
        for detection in self.recent_detections:
            top_ips[detection['src_ip']] += 1
            
            if detection['status'] in ['suspicious', 'attack']:
                suspicious_ips[detection['src_ip']] += 1
        
        stats['top_active_ips'] = dict(top_ips.most_common(5))
        stats['top_suspicious_ips'] = dict(suspicious_ips.most_common(5))
        
        # Añadir baseline
        stats['network_baseline'] = {
            'avg_flows_per_min': self.network_baseline['avg_flows_per_min'],
            'avg_packets_per_flow': self.network_baseline['avg_packets_per_flow'],
            'last_update': datetime.datetime.fromtimestamp(self.network_baseline['last_update'])
        }
        
        return stats


class IDSApplication:
    """Aplicación GUI mejorada para el sistema de detección de intrusiones"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema Avanzado de Detección de Intrusiones")
        self.root.geometry("1280x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables para configuración
        self.interface_var = tk.StringVar(value="Wi-Fi")
        self.model_path_var = tk.StringVar(value="model/modelo_rf_optimizado.pkl")
        self.threshold_normal_var = tk.DoubleVar(value=CONFIG['NORMAL_THRESHOLD'])
        self.threshold_suspicious_var = tk.DoubleVar(value=CONFIG['SUSPICIOUS_THRESHOLD'])
        
        # Monitor de red
        self.monitor = None
        self.update_thread = None
        self.stop_update = threading.Event()
        
        # Crear la interfaz
        self.create_widgets()
        
        # Variable para rastrear si el monitoreo está activo
        self.monitoring = False
        
        # Inicializar modo avanzado
        self.advanced_mode = False
    
    def create_widgets(self):
        """Crea los widgets de la interfaz con más opciones y visualizaciones"""
        # Notebook principal para pestañas
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Pestaña principal
        main_tab = ttk.Frame(notebook)
        notebook.add(main_tab, text="Monitor")
        
        # Pestaña de configuración
        config_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="Configuración")
        
        # Pestaña de análisis
        analysis_tab = ttk.Frame(notebook)
        notebook.add(analysis_tab, text="Análisis")
        
        # Configurar cada pestaña
        self._setup_main_tab(main_tab)
        self._setup_config_tab(config_tab)
        self._setup_analysis_tab(analysis_tab)
        
        # Barra de estado
        self.status_var = tk.StringVar(value="Listo para iniciar")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _setup_main_tab(self, parent):
        """Configura la pestaña principal con monitoreo en tiempo real"""
        # Panel de control
        control_frame = ttk.LabelFrame(parent, text="Control", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Configuración de interfaz
        ttk.Label(control_frame, text="Interfaz de red:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(control_frame, textvariable=self.interface_var, width=15).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Configuración de modelo
        ttk.Label(control_frame, text="Ruta del modelo:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(control_frame, textvariable=self.model_path_var, width=50).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Botones de control
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Iniciar monitoreo", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Detener monitoreo", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Panel de estadísticas
        stats_frame = ttk.LabelFrame(parent, text="Estadísticas en tiempo real", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Métricas básicas
        metrics_frame = ttk.Frame(stats_frame)
        metrics_frame.pack(fill=tk.X)
        
        # Contadores
        self.flow_count_var = tk.StringVar(value="0")
        self.normal_count_var = tk.StringVar(value="0")
        self.suspicious_count_var = tk.StringVar(value="0")
        self.attack_count_var = tk.StringVar(value="0")
        
        ttk.Label(metrics_frame, text="Flujos activos:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.flow_count_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(metrics_frame, text="Normal:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.normal_count_var, foreground="green").grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(metrics_frame, text="Sospechosos:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.suspicious_count_var, foreground="orange").grid(row=0, column=5, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(metrics_frame, text="Ataques:").grid(row=0, column=6, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.attack_count_var, foreground="red").grid(row=0, column=7, sticky=tk.W, padx=5, pady=2)
        
        # Contadores por tipo de ataque
        attack_frame = ttk.Frame(stats_frame)
        attack_frame.pack(fill=tk.X, pady=5)
        
        self.scan_count_var = tk.StringVar(value="0")
        self.dos_count_var = tk.StringVar(value="0")
        self.web_count_var = tk.StringVar(value="0")
        self.other_count_var = tk.StringVar(value="0")
        
        ttk.Label(attack_frame, text="Escaneos:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(attack_frame, textvariable=self.scan_count_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(attack_frame, text="DoS/DDoS:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(attack_frame, textvariable=self.dos_count_var).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(attack_frame, text="Web:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=2)
        ttk.Label(attack_frame, textvariable=self.web_count_var).grid(row=0, column=5, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(attack_frame, text="Otros:").grid(row=0, column=6, sticky=tk.W, padx=5, pady=2)
        ttk.Label(attack_frame, textvariable=self.other_count_var).grid(row=0, column=7, sticky=tk.W, padx=5, pady=2)
        
        # Panel de gráficos
        chart_frame = ttk.Frame(parent)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Crear subplots para gráficos
        self.fig = plt.figure(figsize=(12, 6))
        gs = self.fig.add_gridspec(2, 2)
        self.ax1 = self.fig.add_subplot(gs[0, 0])  # Distribución general
        self.ax2 = self.fig.add_subplot(gs[0, 1])  # Tipos de ataque
        self.ax3 = self.fig.add_subplot(gs[1, :])  # Línea de tiempo
        
        self.fig.tight_layout(pad=3.0)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Registro de eventos
        log_frame = ttk.LabelFrame(parent, text="Registro de eventos", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def _setup_config_tab(self, parent):
        """Configura la pestaña de configuración avanzada"""
        # Frame principal
        config_frame = ttk.Frame(parent, padding=10)
        config_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configuración de umbrales
        threshold_frame = ttk.LabelFrame(config_frame, text="Umbrales de detección", padding=10)
        threshold_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Umbral normal
        ttk.Label(threshold_frame, text="Umbral Normal:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        normal_scale = ttk.Scale(threshold_frame, from_=0.01, to=0.5, orient=tk.HORIZONTAL, 
                                 variable=self.threshold_normal_var, length=200)
        normal_scale.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(threshold_frame, textvariable=self.threshold_normal_var).grid(row=0, column=2, padx=5, pady=5)
        
        # Umbral sospechoso
        ttk.Label(threshold_frame, text="Umbral Sospechoso:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        suspicious_scale = ttk.Scale(threshold_frame, from_=0.05, to=0.8, orient=tk.HORIZONTAL, 
                                     variable=self.threshold_suspicious_var, length=200)
        suspicious_scale.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(threshold_frame, textvariable=self.threshold_suspicious_var).grid(row=1, column=2, padx=5, pady=5)
        
        # Botón para aplicar configuración
        ttk.Button(threshold_frame, text="Aplicar umbrales", command=self.apply_thresholds).grid(
            row=2, column=0, columnspan=3, pady=10)
        
        # Configuración de detección
        detection_frame = ttk.LabelFrame(config_frame, text="Parámetros de detección", padding=10)
        detection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Parámetros ajustables (ejemplos)
        self.scan_threshold_var = tk.IntVar(value=CONFIG['PORT_SCAN_THRESHOLD'])
        self.max_conn_var = tk.IntVar(value=CONFIG['MAX_CONN_PER_SEC'])
        
        ttk.Label(detection_frame, text="Puertos mínimos para escaneo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(detection_frame, from_=3, to=20, textvariable=self.scan_threshold_var, width=5).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Conexiones máximas/seg:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(detection_frame, from_=5, to=100, textvariable=self.max_conn_var, width=5).grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Botón para aplicar configuración
        ttk.Button(detection_frame, text="Aplicar parámetros", command=self.apply_detection_params).grid(
            row=2, column=0, columnspan=2, pady=10)
        
        # Opciones avanzadas
        advanced_frame = ttk.LabelFrame(config_frame, text="Opciones avanzadas", padding=10)
        advanced_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Modo avanzado
        self.advanced_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Modo de depuración", variable=self.advanced_mode_var,
                       command=self.toggle_advanced_mode).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Botón para exportar logs
        ttk.Button(advanced_frame, text="Exportar registros", command=self.export_logs).grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Botón para cargar configuración
        ttk.Button(advanced_frame, text="Cargar configuración", command=self.load_config).grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Botón para guardar configuración
        ttk.Button(advanced_frame, text="Guardar configuración", command=self.save_config).grid(
            row=1, column=2, sticky=tk.W, padx=5, pady=5)
    
    def _setup_analysis_tab(self, parent):
        """Configura la pestaña de análisis detallado"""
        # Frame principal
        analysis_frame = ttk.Frame(parent, padding=10)
        analysis_frame.pack(fill=tk.BOTH, expand=True)
        
        # Panel superior para selección
        top_frame = ttk.Frame(analysis_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Selector de análisis
        ttk.Label(top_frame, text="Tipo de análisis:").pack(side=tk.LEFT, padx=5)
        self.analysis_var = tk.StringVar(value="timeline")
        analysis_combo = ttk.Combobox(top_frame, textvariable=self.analysis_var, 
                                      values=["timeline", "ip_details", "port_details", "attack_details"])
        analysis_combo.pack(side=tk.LEFT, padx=5)
        analysis_combo.bind("<<ComboboxSelected>>", self.update_analysis)
        
        ttk.Button(top_frame, text="Analizar", command=self.update_analysis).pack(side=tk.LEFT, padx=5)
        
        # Panel para detalles de IP
        self.ip_var = tk.StringVar()
        ip_frame = ttk.Frame(top_frame)
        ip_frame.pack(side=tk.LEFT, padx=20)
        ttk.Label(ip_frame, text="Dirección IP:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(ip_frame, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(ip_frame, text="Analizar IP", command=lambda: self.analyze_ip(self.ip_var.get())).pack(side=tk.LEFT, padx=5)
        
        # Panel de gráficos para análisis
        chart_frame = ttk.LabelFrame(analysis_frame, text="Análisis detallado", padding=10)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.analysis_fig = plt.figure(figsize=(12, 6))
        self.analysis_canvas = FigureCanvasTkAgg(self.analysis_fig, master=chart_frame)
        self.analysis_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def apply_thresholds(self):
        if self.monitor:
            self.monitor.thresholds = {
                'normal': self.threshold_normal_var.get(),
                'suspicious': self.threshold_suspicious_var.get()
            }
            logger.info(f"Umbrales actualizados: Normal={self.threshold_normal_var.get()}, Sospechoso={self.threshold_suspicious_var.get()}")
            messagebox.showinfo("Configuración", "Umbrales actualizados correctamente")
    
    def apply_detection_params(self):
        """Aplica los parámetros de detección configurados"""
        CONFIG['PORT_SCAN_THRESHOLD'] = self.scan_threshold_var.get()
        CONFIG['MAX_CONN_PER_SEC'] = self.max_conn_var.get()
        logger.info(f"Parámetros actualizados: PORT_SCAN_THRESHOLD={CONFIG['PORT_SCAN_THRESHOLD']}, MAX_CONN_PER_SEC={CONFIG['MAX_CONN_PER_SEC']}")
        messagebox.showinfo("Configuración", "Parámetros actualizados correctamente")
    
    def toggle_advanced_mode(self):
        """Activa o desactiva el modo avanzado"""
        self.advanced_mode = self.advanced_mode_var.get()
        if self.advanced_mode:
            logger.info("Modo avanzado activado")
            # Mostrar información avanzada en logs
            if self.log_text:
                self.log_text.insert(tk.END, "--- MODO AVANZADO ACTIVADO: Se mostrarán detalles adicionales ---\n")
        else:
            logger.info("Modo avanzado desactivado")
    
    def export_logs(self):
        """Exporta los logs a un archivo"""
        try:
            filename = f"ids_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Exportar", f"Logs exportados correctamente a {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar logs: {e}")
    
    def load_config(self):
        """Carga configuración desde un archivo"""
        try:
            # Simulación - en producción cargaría de un archivo
            self.threshold_normal_var.set(0.05)
            self.threshold_suspicious_var.set(0.15)
            self.scan_threshold_var.set(5)
            self.max_conn_var.set(20)
            messagebox.showinfo("Configuración", "Configuración cargada correctamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar configuración: {e}")
    
    def save_config(self):
        """Guarda configuración en un archivo"""
        try:
            # Simulación - en producción guardaría en un archivo
            config = {
                'NORMAL_THRESHOLD': self.threshold_normal_var.get(),
                'SUSPICIOUS_THRESHOLD': self.threshold_suspicious_var.get(),
                'PORT_SCAN_THRESHOLD': self.scan_threshold_var.get(),
                'MAX_CONN_PER_SEC': self.max_conn_var.get()
            }
            logger.info(f"Configuración guardada: {config}")
            messagebox.showinfo("Configuración", "Configuración guardada correctamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar configuración: {e}")
    
    def update_analysis(self, event=None):
        """Actualiza el análisis según el tipo seleccionado"""
        analysis_type = self.analysis_var.get()
        
        # Limpiar figura actual
        self.analysis_fig.clear()
        
        if not self.monitor or not self.monitor.recent_detections:
            # No hay datos para analizar
            ax = self.analysis_fig.add_subplot(111)
            ax.text(0.5, 0.5, "No hay datos para analizar", horizontalalignment='center', verticalalignment='center')
            self.analysis_canvas.draw()
            return
        
        if analysis_type == "timeline":
            self._show_timeline_analysis()
        elif analysis_type == "ip_details":
            self._show_ip_analysis()
        elif analysis_type == "port_details":
            self._show_port_analysis()
        elif analysis_type == "attack_details":
            self._show_attack_analysis()
        
        self.analysis_canvas.draw()
    
    def _show_timeline_analysis(self):
        """Muestra análisis de línea de tiempo"""
        # Extraer datos para análisis
        detections = self.monitor.recent_detections
        timestamps = [d['timestamp'] for d in detections]
        values = [d['probability'] for d in detections]
        statuses = [d['status'] for d in detections]
        
        # Crear colores basados en estado
        colors = []
        for status in statuses:
            if status == 'normal':
                colors.append('green')
            elif status == 'suspicious':
                colors.append('orange')
            else:
                colors.append('red')
        
        # Crear gráfico
        ax1 = self.analysis_fig.add_subplot(211)
        ax1.scatter(timestamps, values, c=colors, alpha=0.7)
        ax1.set_title('Línea de tiempo de detecciones')
        ax1.set_ylabel('Probabilidad')
        ax1.set_ylim(0, 1)
        ax1.axhline(y=self.monitor.thresholds['normal'], color='g', linestyle='--', alpha=0.7)
        ax1.axhline(y=self.monitor.thresholds['suspicious'], color='r', linestyle='--', alpha=0.7)
        
        # Histograma de probabilidades
        ax2 = self.analysis_fig.add_subplot(212)
        ax2.hist(values, bins=20, range=(0, 1), alpha=0.7)
        ax2.set_title('Distribución de probabilidades')
        ax2.set_xlabel('Probabilidad')
        ax2.set_ylabel('Frecuencia')
        
        self.analysis_fig.tight_layout()
    
    def _show_ip_analysis(self):
        """Muestra análisis por IP"""
        # Extraer datos para análisis
        detections = self.monitor.recent_detections
        
        # Contar ocurrencias de IPs
        src_ips = Counter([d['src_ip'] for d in detections])
        dst_ips = Counter([d['dst_ip'] for d in detections])
        
        # Top 10 IPs
        top_src = src_ips.most_common(10)
        top_dst = dst_ips.most_common(10)
        
        # Crear gráficos
        ax1 = self.analysis_fig.add_subplot(121)
        ax1.barh([ip[0] for ip in top_src], [ip[1] for ip in top_src])
        ax1.set_title('Top 10 IPs origen')
        ax1.set_xlabel('Recuento')
        
        ax2 = self.analysis_fig.add_subplot(122)
        ax2.barh([ip[0] for ip in top_dst], [ip[1] for ip in top_dst])
        ax2.set_title('Top 10 IPs destino')
        ax2.set_xlabel('Recuento')
        
        self.analysis_fig.tight_layout()
    
    def _show_port_analysis(self):
        """Muestra análisis de puertos"""
        # Extraer datos para análisis
        detections = self.monitor.recent_detections
        
        # Extraer puertos
        src_ports = []
        dst_ports = []
        
        for d in detections:
            try:
                src_ports.append(int(d['src_ip'].split(':')[1]))
            except:
                pass
                
            try:
                dst_ports.append(int(d['dst_ip'].split(':')[1]))
            except:
                pass
        
        src_port_counts = Counter(src_ports)
        dst_port_counts = Counter(dst_ports)
        
        # Top 10 puertos
        top_src = src_port_counts.most_common(10)
        top_dst = dst_port_counts.most_common(10)
        
        # Crear gráficos
        ax1 = self.analysis_fig.add_subplot(121)
        ax1.bar([str(p[0]) for p in top_src], [p[1] for p in top_src])
        ax1.set_title('Top 10 puertos origen')
        ax1.set_xlabel('Puerto')
        ax1.set_ylabel('Recuento')
        
        ax2 = self.analysis_fig.add_subplot(122)
        ax2.bar([str(p[0]) for p in top_dst], [p[1] for p in top_dst])
        ax2.set_title('Top 10 puertos destino')
        ax2.set_xlabel('Puerto')
        
        self.analysis_fig.tight_layout()
    
    def _show_attack_analysis(self):
        """Muestra análisis detallado de ataques"""
        # Filtrar solo los ataques
        attacks = [d for d in self.monitor.recent_detections if d['status'] == 'attack']
        
        if not attacks:
            ax = self.analysis_fig.add_subplot(111)
            ax.text(0.5, 0.5, "No se han detectado ataques", horizontalalignment='center', verticalalignment='center')
            return
        # Contar tipos de ataque
        attack_types = Counter([a.get('attack_type', 'other') for a in attacks])
        
        # Primera gráfica: distribución de tipos de ataque
        ax1 = self.analysis_fig.add_subplot(121)
        labels = list(attack_types.keys())
        sizes = list(attack_types.values())
        ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax1.axis('equal')
        ax1.set_title('Distribución de tipos de ataque')
        
        # Segunda gráfica: línea de tiempo de ataques
        ax2 = self.analysis_fig.add_subplot(122)
        timestamps = [a['timestamp'] for a in attacks]
        types = [a.get('attack_type', 'other') for a in attacks]
        
        # Asignar colores por tipo
        colors = {'scan': 'blue', 'dos': 'red', 'web': 'purple', 'brute': 'brown', 'other': 'gray'}
        point_colors = [colors.get(t, 'gray') for t in types]
        
        # Crear gráfico de dispersión
        ax2.scatter(timestamps, [1] * len(timestamps), c=point_colors, s=50)
        ax2.set_yticks([])
        ax2.set_title('Línea de tiempo de ataques')
        
        # Añadir leyenda
        from matplotlib.lines import Line2D
        legend_elements = [Line2D([0], [0], marker='o', color='w', markerfacecolor=color, label=type_, markersize=8)
                            for type_, color in colors.items() if type_ in types]
        ax2.legend(handles=legend_elements, loc='upper center')
        
        self.analysis_fig.tight_layout()
    
    def analyze_ip(self, ip):
        """Analiza una IP específica"""
        if not ip or not self.monitor:
            messagebox.showinfo("Análisis IP", "Ingrese una IP válida y asegúrese de que el monitoreo esté activo")
            return
        
        # Filtrar detecciones para esta IP
        ip_detections = [d for d in self.monitor.recent_detections 
                        if d['src_ip'] == ip or d['dst_ip'] == ip]
        
        if not ip_detections:
            messagebox.showinfo("Análisis IP", f"No hay datos para la IP {ip}")
            return
        
        # Limpiar figura actual
        self.analysis_fig.clear()
        
        # Gráfico 1: Probabilidades a lo largo del tiempo
        ax1 = self.analysis_fig.add_subplot(221)
        timestamps = [d['timestamp'] for d in ip_detections]
        probs = [d['probability'] for d in ip_detections]
        statuses = [d['status'] for d in ip_detections]
        colors = ['green' if s == 'normal' else 'orange' if s == 'suspicious' else 'red' for s in statuses]
        
        ax1.scatter(timestamps, probs, c=colors)
        ax1.set_title(f'Análisis de IP: {ip}')
        ax1.set_ylabel('Probabilidad')
        ax1.set_ylim(0, 1)
        
        # Gráfico 2: Protocolos usados
        ax2 = self.analysis_fig.add_subplot(222)
        protocols = Counter([d['protocol'] for d in ip_detections])
        ax2.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        ax2.set_title('Protocolos')
        
        # Gráfico 3: Estadísticas de paquetes
        ax3 = self.analysis_fig.add_subplot(223)
        packet_counts = [d['packet_count'] for d in ip_detections]
        ax3.hist(packet_counts, bins=min(20, len(packet_counts)))
        ax3.set_title('Distribución de conteo de paquetes')
        ax3.set_xlabel('Conteo de paquetes')
        
        # Gráfico 4: Info de flags si está disponible
        ax4 = self.analysis_fig.add_subplot(224)
        
        # Verificar si hay información de flags
        if 'flags' in ip_detections[0]:
            # Sumar flags a través de todas las detecciones
            all_flags = Counter()
            for d in ip_detections:
                if isinstance(d['flags'], dict):
                    for flag, count in d['flags'].items():
                        all_flags[flag] += count
            
            # Mostrar gráfico de barras de flags
            ax4.bar(all_flags.keys(), all_flags.values())
            ax4.set_title('Banderas TCP')
        else:
            ax4.text(0.5, 0.5, "No hay datos de banderas TCP", 
                    horizontalalignment='center', verticalalignment='center')
        
        self.analysis_fig.tight_layout()
        self.analysis_canvas.draw()
        
        # Mostrar resumen en log
        summary = (f"Análisis de IP {ip}: {len(ip_detections)} detecciones, "
                f"Máx. prob: {max(probs):.4f}, "
                f"Protocolos: {dict(protocols)}")
        
        if self.log_text:
            self.log_text.insert(tk.END, f"\n{summary}\n")
    
    def update_ui(self):
        """Actualiza la interfaz con los datos del monitor"""
        while not self.stop_update.is_set():
            try:
                if self.monitor:
                    # Obtener estadísticas
                    stats = self.monitor.get_stats()
                    
                    # Actualizar contadores básicos
                    self.flow_count_var.set(str(stats['active_flows']))
                    self.normal_count_var.set(str(stats['normal_count']))
                    self.suspicious_count_var.set(str(stats['suspicious_count']))
                    self.attack_count_var.set(str(stats['attack_count']))
                    
                    # Actualizar contadores por tipo de ataque
                    if 'attack_types' in stats:
                        self.scan_count_var.set(str(stats['attack_types'].get('scan', 0)))
                        self.dos_count_var.set(str(stats['attack_types'].get('dos', 0)))
                        self.web_count_var.set(str(stats['attack_types'].get('web', 0)))
                        self.other_count_var.set(str(stats['attack_types'].get('other', 0) + 
                                                    stats['attack_types'].get('brute', 0)))
                    
                    # Actualizar gráficos
                    self.update_charts(stats)
                    
                    # Actualizar registro de eventos
                    self.update_event_log(stats['recent_detections'][-10:] if stats['recent_detections'] else [])
                    
                    # Actualizar barra de estado
                    self.status_var.set(f"Último escaneo: {stats['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - " +
                                    f"Total analizado: {stats['total_analyzed']}")
            
            except Exception as e:
                logger.error(f"Error actualizando UI: {e}")
            
            time.sleep(1)  # Actualizar cada segundo
        
    def update_charts(self, stats):
        """Actualiza los gráficos con las nuevas estadísticas"""
        try:
            # Limpiar gráficos
            self.ax1.clear()
            self.ax2.clear()
            self.ax3.clear()
            
            # Gráfico 1: Distribución general de alertas
            labels = ['Normal', 'Sospechoso', 'Ataque']
            values = [stats['normal_count'], stats['suspicious_count'], stats['attack_count']]
            colors = ['green', 'orange', 'red']
            
            # Solo mostrar gráfico si hay datos
            if sum(values) > 0:
                self.ax1.pie(values, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
                self.ax1.set_title('Distribución de Alertas')
            else:
                self.ax1.text(0.5, 0.5, "Sin datos", horizontalalignment='center', verticalalignment='center')
            
            # Gráfico 2: Tipos de ataques
            if 'attack_types' in stats:
                attack_labels = ['Escaneo', 'DoS', 'Web', 'Otros']
                attack_values = [
                    stats['attack_types'].get('scan', 0),
                    stats['attack_types'].get('dos', 0),
                    stats['attack_types'].get('web', 0),
                    stats['attack_types'].get('other', 0) + stats['attack_types'].get('brute', 0)
                ]
                
                if sum(attack_values) > 0:
                    self.ax2.bar(attack_labels, attack_values, color=['blue', 'red', 'purple', 'gray'])
                    self.ax2.set_title('Tipos de Ataques')
                    self.ax2.set_ylabel('Recuento')
                else:
                    self.ax2.text(0.5, 0.5, "No se han detectado ataques", 
                                horizontalalignment='center', verticalalignment='center')
            
            # Gráfico 3: Línea de tiempo de alertas
            detections = stats['recent_detections']
            if detections:
                # Tomar últimos N eventos para la línea de tiempo
                recent = detections[-50:] if len(detections) > 50 else detections
                
                # Extraer datos para gráfico
                timestamps = [d['timestamp'] for d in recent]
                values = [d['probability'] for d in recent]
                statuses = [d['status'] for d in recent]
                
                # Crear colores basados en estado
                colors = []
                for status in statuses:
                    if status == 'normal':
                        colors.append('green')
                    elif status == 'suspicious':
                        colors.append('orange')
                    else:
                        colors.append('red')
                
                # Crear gráfico de dispersión
                self.ax3.scatter(timestamps, values, c=colors, alpha=0.7)
                self.ax3.set_title('Línea de tiempo de alertas recientes')
                self.ax3.set_ylabel('Probabilidad')
                self.ax3.set_ylim(0, 1)
                
                # Añadir líneas de umbral
                self.ax3.axhline(y=self.monitor.thresholds['normal'], color='g', linestyle='--', alpha=0.7)
                self.ax3.axhline(y=self.monitor.thresholds['suspicious'], color='r', linestyle='--', alpha=0.7)
                
                # Formatear eje X para fechas
                self.ax3.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M:%S'))
            else:
                self.ax3.text(0.5, 0.5, "Sin datos de alertas recientes", 
                            horizontalalignment='center', verticalalignment='center')
            
            # Ajustar diseño
            self.fig.tight_layout()
            
            # Refrescar canvas
            self.canvas.draw()
        
        except Exception as e:
            logger.error(f"Error actualizando gráficos: {e}")
    
    def update_event_log(self, recent_detections):
        """Actualiza el registro de eventos con las detecciones recientes"""
        try:
            # Limpiar log si hay demasiadas entradas
            if self.log_text.index('end-1c').split('.')[0] > '1000':
                self.log_text.delete(1.0, tk.END)
            
            # Añadir nuevas detecciones
            for detection in reversed(recent_detections):
                timestamp = detection['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                
                # Formato según el tipo de alerta
                if detection['status'] == 'normal':
                    tag = 'normal'
                    prefix = "[NORMAL]"
                elif detection['status'] == 'suspicious':
                    tag = 'suspicious'
                    prefix = "[SOSPECHOSO]"
                else:
                    tag = 'attack'
                    prefix = f"[ATAQUE-{detection.get('attack_type', 'desconocido').upper()}]"
                
                # Mensaje básico
                msg = f"{timestamp} {prefix} {detection['src_ip']} -> {detection['dst_ip']} ({detection['protocol']}) " + \
                    f"Prob: {detection['probability']:.4f}"
                
                # Información adicional en modo avanzado
                if self.advanced_mode:
                    if 'flags' in detection:
                        msg += f" Flags: {detection['flags']}"
                    if 'packet_count' in detection:
                        msg += f" Paquetes: {detection['packet_count']}"
                    if 'ports_accessed' in detection and detection['ports_accessed']:
                        msg += f" Puertos: {detection['ports_accessed'][:5]}"
                
                msg += "\n"
                
                # Insertar mensaje al principio
                self.log_text.insert(1.0, msg)
                
                # Configurar color según el tipo
                self.log_text.tag_add(tag, "1.0", "1.end")
            
            # Configurar tags para colores
            self.log_text.tag_config('normal', foreground='green')
            self.log_text.tag_config('suspicious', foreground='orange')
            self.log_text.tag_config('attack', foreground='red')
        
        except Exception as e:
            logger.error(f"Error actualizando log: {e}")
        
    def start_monitoring(self):
        """Inicia el monitoreo de red"""
        try:
            # Obtener configuración
            interface = self.interface_var.get()
            model_path = self.model_path_var.get()
            
            if not os.path.exists(model_path):
                self.show_error(f"No se encontró el modelo en {model_path}")
                return
            
            # Inicializar monitor
            self.monitor = EnhancedNetworkMonitor(model_path=model_path, interface=interface)
            
            # Actualizar umbrales desde la UI
            self.monitor.thresholds = {
                'normal': self.threshold_normal_var.get(),
                'suspicious': self.threshold_suspicious_var.get()
            }
            
            # Iniciar captura
            self.monitor.start_capture()
            
            # Iniciar hilo de actualización de UI
            self.stop_update.clear()
            self.update_thread = threading.Thread(target=self.update_ui)
            self.update_thread.daemon = True
            self.update_thread.start()
            
            # Actualizar estado de botones
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set("Monitoreo iniciado...")
            self.monitoring = True
            
            # Log
            logger.info(f"Monitoreo iniciado en la interfaz {interface}")
            self.log_text.insert(tk.END, f"Sistema iniciado - Monitoreo en {interface}\n")
            self.log_text.insert(tk.END, f"Umbrales: Normal={self.threshold_normal_var.get()}, Sospechoso={self.threshold_suspicious_var.get()}\n")
        
        except Exception as e:
            self.show_error(f"Error al iniciar el monitoreo: {e}")
    
    def stop_monitoring(self):
        """Detiene el monitoreo de red"""
        if self.monitor:
            # Detener captura
            self.monitor.stop_capture_thread()
            
            # Detener actualización de UI
            self.stop_update.set()
            if self.update_thread:
                self.update_thread.join(timeout=2.0)
            
            # Actualizar estado de botones
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("Monitoreo detenido")
            self.monitoring = False
            
            # Log
            logger.info("Monitoreo detenido")
            self.log_text.insert(tk.END, "Sistema detenido\n")
    
    def show_error(self, message):
        """Muestra un mensaje de error"""
        logger.error(message)
        messagebox.showerror("Error", message)
    
    def on_closing(self):
        """Maneja el cierre de la aplicación"""
        if self.monitoring:
            self.stop_monitoring()
        
        self.root.destroy()


    # Función para modo CLI
    def run_cli_mode(model_path, interface, duration):
        """Ejecuta el sistema en modo CLI por un tiempo determinado"""
        print(f"Iniciando monitoreo en interfaz {interface} durante {duration} segundos")
        
        try:
            # Inicializar monitor
            monitor = EnhancedNetworkMonitor(model_path=model_path, interface=interface)
            
            # Iniciar captura
            monitor.start_capture()
            
            # Ejecutar por duración especificada
            start_time = time.time()
            try:
                while time.time() - start_time < duration:
                    # Obtener estadísticas cada 5 segundos
                    if int((time.time() - start_time) % 5) == 0:
                        stats = monitor.get_stats()
                        print(f"\nEstadísticas ({stats['timestamp']}):")
                        print(f"Flujos activos: {stats['active_flows']}")
                        print(f"Normal: {stats['normal_count']} | Sospechosos: {stats['suspicious_count']} | Ataques: {stats['attack_count']}")
                        
                        # Mostrar tipos de ataque si hay alguno
                        if stats['attack_count'] > 0 and 'attack_types' in stats:
                            print("Tipos de ataque detectados:")
                            for attack_type, count in stats['attack_types'].items():
                                if count > 0:
                                    print(f"  - {attack_type}: {count}")
                    
                    time.sleep(1)
            
            except KeyboardInterrupt:
                print("\nInterrumpido por el usuario")
            
            # Detener captura
            monitor.stop_capture_thread()
            
            # Mostrar estadísticas finales
            stats = monitor.get_stats()
            print("\nEstadísticas finales:")
            print(f"Total de flujos analizados: {stats['total_analyzed']}")
            print(f"Normal: {stats['normal_count']} | Sospechosos: {stats['suspicious_count']} | Ataques: {stats['attack_count']}")
            
            if stats['attack_count'] > 0:
                print("\nResumen de ataques por tipo:")
                for attack_type, count in stats['attack_types'].items():
                    if count > 0:
                        print(f"  - {attack_type}: {count}")
            
            if stats['recent_detections']:
                print("\nÚltimas detecciones:")
                for detection in stats['recent_detections'][-5:]:
                    status = detection['status'].upper()
                    if status == "ATTACK" and 'attack_type' in detection:
                        status = f"ATTACK-{detection['attack_type'].upper()}"
                    
                    print(f"[{status}] {detection['src_ip']} -> {detection['dst_ip']} ({detection['protocol']}) - " +
                        f"Prob: {detection['probability']:.4f}")
        
        except Exception as e:
            logger.error(f"Error en modo CLI: {e}")
            print(f"Error: {e}")


def main():
        """Función principal"""
        # Configurar argumentos de línea de comandos
        parser = argparse.ArgumentParser(description="Sistema Avanzado de Detección de Intrusiones en Tiempo Real")
        parser.add_argument("--model", type=str, default="model/modelo_rf_optimizado.pkl", 
                            help="Ruta al modelo entrenado")
        parser.add_argument("--interface", type=str, default="Wi-Fi", 
                            help="Interfaz de red a monitorear")
        parser.add_argument("--cli", action="store_true", 
                            help="Ejecutar en modo línea de comandos (sin GUI)")
        parser.add_argument("--duration", type=int, default=300, 
                            help="Duración del monitoreo en modo CLI (segundos)")
        parser.add_argument("--threshold-normal", type=float, default=CONFIG['NORMAL_THRESHOLD'],
                            help=f"Umbral para tráfico normal (default: {CONFIG['NORMAL_THRESHOLD']})")
        parser.add_argument("--threshold-suspicious", type=float, default=CONFIG['SUSPICIOUS_THRESHOLD'],
                            help=f"Umbral para tráfico sospechoso (default: {CONFIG['SUSPICIOUS_THRESHOLD']})")
        
        args = parser.parse_args()
        
        # Actualizar umbrales desde argumentos
        CONFIG['NORMAL_THRESHOLD'] = args.threshold_normal
        CONFIG['SUSPICIOUS_THRESHOLD'] = args.threshold_suspicious
        
        # Verificar si el modelo existe
        if not os.path.exists(args.model):
            print(f"Error: No se encontró el modelo en {args.model}")
            return
        
        # Ejecutar en modo CLI o GUI
        if args.cli:
            run_cli_mode(args.model, args.interface, args.duration)
        else:
            try:
                root = tk.Tk()
                app = IDSApplication(root)
                root.mainloop()
            except Exception as e:
                logger.error(f"Error en la aplicación GUI: {e}")
                print(f"Error: {e}")


if __name__ == "__main__":
        main()
        logger.info("Sistema de Detección de Intrusiones detenido.")