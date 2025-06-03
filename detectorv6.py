#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Detección de Intrusiones en Tiempo Real
--------------------------------------------------
Este sistema captura tráfico de red, extrae características de flujos y utiliza
un modelo de aprendizaje automático para detectar intrusiones en tiempo real.

Autor: [Tu Nombre]
Fecha: 2025-06-02
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
from collections import defaultdict, deque
from sklearn.preprocessing import StandardScaler
import warnings
import tkinter as tk
from tkinter import ttk, scrolledtext
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

class FlowRecord:
    """Clase para almacenar información de flujos de red"""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.start_time = None
        self.last_update = time.time()
        
        # Estadísticas de flujo
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
    
    def add_packet(self, packet, timestamp):
        """Añade un paquete al flujo y actualiza estadísticas"""
        if not self.start_time:
            self.start_time = timestamp
        
        # Calcular tiempos entre llegadas
        if self.last_packet_time:
            iat = timestamp - self.last_packet_time
            self.inter_arrival_times.append(iat)
        
        self.last_packet_time = timestamp
        self.flow_duration = timestamp - self.start_time
        self.last_update = time.time()
        
        # Almacenar longitud de paquete
        try:
            packet_len = int(packet.length)
            self.packet_lengths.append(packet_len)
            
            # Determinar dirección del paquete
            is_forward = False
            
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                is_forward = (src_ip == self.src_ip and dst_ip == self.dst_ip)
            
            # Actualizar estadísticas según la dirección
            if is_forward:
                self.fwd_packets.append(packet_len)
                if len(self.fwd_packets) > 1:
                    self.fwd_inter_arrival_times.append(iat)
            else:
                self.bwd_packets.append(packet_len)
                if len(self.bwd_packets) > 1:
                    self.bwd_inter_arrival_times.append(iat)
            
            # Procesar banderas si es TCP
            if hasattr(packet, 'tcp'):
                for flag in self.flags:
                    if hasattr(packet.tcp, flag.lower()) and int(getattr(packet.tcp, flag.lower())) == 1:
                        self.flags[flag] += 1
        
        except Exception as e:
            logger.warning(f"Error procesando paquete: {e}")
        
        self.packets.append(packet)
    
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


class NetworkMonitor:
    """Clase principal para monitoreo de red e identificación de intrusiones"""
    
    def __init__(self, model_path, interface='eth0', timeout=60):
        """
        Inicializa el monitor de red
        
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
        
        # Cola para registro de detecciones recientes (timestamp, tipo, descripción)
        self.recent_detections = deque(maxlen=100)
        
        # Umbrales de clasificación
        self.thresholds = {
            'normal': 0.3,      # probabilidad < 0.3 -> normal
            'suspicious': 0.7   # 0.3 <= probabilidad < 0.7 -> sospechoso
                                # probabilidad >= 0.7 -> ataque
        }
    
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
        """Procesa un paquete y lo añade al flujo correspondiente"""
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
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        
        # Añadir paquete al flujo correspondiente
        with self.flow_lock:
            if flow_id not in self.flows:
                self.flows[flow_id] = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
            
            timestamp = float(packet.sniff_timestamp)
            self.flows[flow_id].add_packet(packet, timestamp)
            
            # Si hay suficientes paquetes, evaluar el flujo
            if len(self.flows[flow_id].packets) >= 10:
                self._evaluate_flow(flow_id)
    
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
            
            if expired_flows:
                logger.debug(f"Se eliminaron {len(expired_flows)} flujos inactivos")
    
    def _evaluate_flow(self, flow_id):
        """Evalúa un flujo para detectar posibles intrusiones"""
        try:
            # Obtener características del flujo
            features = self.flows[flow_id].get_features()
            
            # Verificar que las características requeridas estén presentes
            missing_features = [f for f in self.selected_features if f not in features]
            if missing_features:
                logger.warning(f"Características faltantes: {missing_features}")
                return
            
            # Crear vector de características en el orden correcto
            X = [features[f] for f in self.selected_features]
            X = np.array([X])
            
            # Aplicar escalado
            X_scaled = self.scaler.transform(X)
            
            # Obtener predicción y probabilidad
            y_pred = self.model.predict(X_scaled)
            y_proba = self.model.predict_proba(X_scaled)[0, 1]  # Probabilidad de ataque
            
            # Clasificar según umbrales
            if y_proba < self.thresholds['normal']:
                status = 'normal'
                level = 'info'
            elif y_proba < self.thresholds['suspicious']:
                status = 'suspicious'
                level = 'warning'
            else:
                status = 'attack'
                level = 'error'
            
            # Actualizar contadores
            self.alert_counts[status] += 1
            
            # Crear mensaje de detección
            flow = self.flows[flow_id]
            msg = (f"[{status.upper()}] "
                   f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} "
                   f"({flow.protocol}) - Prob: {y_proba:.4f}")
            
            # Registrar según nivel
            if level == 'info':
                logger.info(msg)
            elif level == 'warning':
                logger.warning(msg)
            else:
                logger.error(msg)
            
            # Guardar detección para visualización
            detection_record = {
                'timestamp': datetime.datetime.now(),
                'flow_id': flow_id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'status': status,
                'probability': y_proba,
                'packet_count': len(flow.packets)
            }
            
            self.recent_detections.append(detection_record)
            
            # Eliminar el flujo evaluado si fue clasificado como ataque
            if status == 'attack':
                del self.flows[flow_id]
        
        except Exception as e:
            logger.error(f"Error evaluando flujo {flow_id}: {e}")
    
    def get_stats(self):
        """Retorna estadísticas de detección"""
        flow_count = len(self.flows)
        
        stats = {
            'timestamp': datetime.datetime.now(),
            'active_flows': flow_count,
            'normal_count': self.alert_counts['normal'],
            'suspicious_count': self.alert_counts['suspicious'],
            'attack_count': self.alert_counts['attack'],
            'total_analyzed': sum(self.alert_counts.values()),
            'recent_detections': list(self.recent_detections)
        }
        
        return stats


class IDSApplication:
    """Aplicación GUI para el sistema de detección de intrusiones"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Detección de Intrusiones")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables para configuración
        self.interface_var = tk.StringVar(value="Wi-Fi")
        self.model_path_var = tk.StringVar(value="model/modelo_rf_optimizado.pkl")

        # Monitor de red
        self.monitor = None
        self.update_thread = None
        self.stop_update = threading.Event()
        
        # Crear la interfaz
        self.create_widgets()
        
        # Variable para rastrear si el monitoreo está activo
        self.monitoring = False
    
    def create_widgets(self):
        """Crea los widgets de la interfaz"""
        # Panel de control
        control_frame = ttk.LabelFrame(self.root, text="Control", padding=10)
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
        stats_frame = ttk.LabelFrame(self.root, text="Estadísticas", padding=10)
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
        ttk.Label(metrics_frame, textvariable=self.normal_count_var).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(metrics_frame, text="Sospechosos:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.suspicious_count_var).grid(row=0, column=5, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(metrics_frame, text="Ataques:").grid(row=0, column=6, sticky=tk.W, padx=5, pady=2)
        ttk.Label(metrics_frame, textvariable=self.attack_count_var).grid(row=0, column=7, sticky=tk.W, padx=5, pady=2)
        
        # Panel de gráficos
        chart_frame = ttk.Frame(self.root)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Gráfico de distribución de alertas
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(12, 4))
        self.fig.tight_layout(pad=3.0)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Registro de eventos
        log_frame = ttk.LabelFrame(self.root, text="Registro de eventos", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Barra de estado
        self.status_var = tk.StringVar(value="Listo para iniciar")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_ui(self):
        """Actualiza la interfaz con los datos del monitor"""
        while not self.stop_update.is_set():
            try:
                if self.monitor:
                    # Obtener estadísticas
                    stats = self.monitor.get_stats()
                    
                    # Actualizar contadores
                    self.flow_count_var.set(str(stats['active_flows']))
                    self.normal_count_var.set(str(stats['normal_count']))
                    self.suspicious_count_var.set(str(stats['suspicious_count']))
                    self.attack_count_var.set(str(stats['attack_count']))
                    
                    # Actualizar gráfico de distribución
                    self.update_distribution_chart(stats)
                    
                    # Actualizar registro de eventos
                    self.update_event_log(stats['recent_detections'][-10:] if stats['recent_detections'] else [])
                    
                    # Actualizar barra de estado
                    self.status_var.set(f"Último escaneo: {stats['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - " +
                                       f"Total analizado: {stats['total_analyzed']}")
            
            except Exception as e:
                logger.error(f"Error actualizando UI: {e}")
            
            time.sleep(1)  # Actualizar cada segundo
    
    def update_distribution_chart(self, stats):
        """Actualiza el gráfico de distribución de alertas"""
        try:
            # Limpiar gráficos
            self.ax1.clear()
            self.ax2.clear()
            
            # Datos para gráfico de distribución
            labels = ['Normal', 'Sospechoso', 'Ataque']
            values = [stats['normal_count'], stats['suspicious_count'], stats['attack_count']]
            colors = ['green', 'orange', 'red']
            
            # Gráfico de torta
            if sum(values) > 0:  # Evitar división por cero
                self.ax1.pie(values, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
                self.ax1.set_title('Distribución de Alertas')
            else:
                self.ax1.text(0.5, 0.5, "Sin datos", horizontalalignment='center', verticalalignment='center')
            
            # Gráfico de barras para los últimos 10 eventos
            recent_types = []
            for detection in stats['recent_detections'][-10:]:
                recent_types.append(detection['status'])
            
            if recent_types:
                type_counts = {'normal': 0, 'suspicious': 0, 'attack': 0}
                for t in recent_types:
                    type_counts[t] += 1
                
                self.ax2.bar(labels, [type_counts['normal'], type_counts['suspicious'], type_counts['attack']], color=colors)
                self.ax2.set_title('Últimos 10 Eventos')
                self.ax2.set_ylim(0, 10)
                self.ax2.set_ylabel('Cantidad')
            else:
                self.ax2.text(0.5, 0.5, "Sin eventos recientes", horizontalalignment='center', verticalalignment='center')
            
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
                    prefix = "[ATAQUE]"
                
                msg = f"{timestamp} {prefix} {detection['src_ip']} -> {detection['dst_ip']} ({detection['protocol']}) " + \
                      f"Prob: {detection['probability']:.4f}\n"
                
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
            self.monitor = NetworkMonitor(model_path=model_path, interface=interface)
            
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
        tk.messagebox.showerror("Error", message)
    
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
        monitor = NetworkMonitor(model_path=model_path, interface=interface)
        
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
        
        if stats['recent_detections']:
            print("\nÚltimas detecciones:")
            for detection in stats['recent_detections'][-5:]:
                status = detection['status'].upper()
                print(f"[{status}] {detection['src_ip']} -> {detection['dst_ip']} ({detection['protocol']}) - Prob: {detection['probability']:.4f}")
    
    except Exception as e:
        logger.error(f"Error en modo CLI: {e}")
        print(f"Error: {e}")


def main():
    """Función principal"""
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="Sistema de Detección de Intrusiones en Tiempo Real")
    parser.add_argument("--model", type=str, default="model/modelo_rf_optimizado.pkl", 
                        help="Ruta al modelo entrenado")
    parser.add_argument("--interface", type=str, default="Wi-Fi", 
                        help="Interfaz de red a monitorear")
    parser.add_argument("--cli", action="store_true", 
                        help="Ejecutar en modo línea de comandos (sin GUI)")
    parser.add_argument("--duration", type=int, default=300, 
                        help="Duración del monitoreo en modo CLI (segundos)")
    
    args = parser.parse_args()
    
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