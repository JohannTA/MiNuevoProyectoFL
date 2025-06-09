#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Detección de Intrusiones en Tiempo Real (Versión Compacta)
---------------------------------------------------------------------
Autor: [Tu Nombre]
Fecha: 2025-06-03
Versión: 3.0
"""

import os, time, joblib, numpy as np, pyshark, argparse, threading, datetime
import logging, ipaddress, json, sys, signal, traceback
from collections import defaultdict, deque, Counter
import warnings

# Configuración
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[logging.FileHandler("ids_detection.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore")

# Configuración global con valores por defecto
CONFIG = {
    'NORMAL_THRESHOLD': 0.05, 'SUSPICIOUS_THRESHOLD': 0.15, 'PORT_SCAN_THRESHOLD': 5,
    'PORT_SCAN_TIME_WINDOW': 10, 'WEB_PORTS': [80, 443, 8080, 8443, 3000, 4200, 5000, 8000],
    'MAX_CONN_PER_SEC': 20, 'MAX_PACKETS_PER_SEC': 100, 'SYN_RATIO_THRESHOLD': 0.8,
    'ENTROPY_THRESHOLD': 0.8, 'SHOW_NORMAL_TRAFFIC': False, 'UPDATE_INTERVAL': 5,
    'LOG_LEVEL': 'INFO', 'MIN_PACKETS_TO_ANALYZE': 5, 'CLEANUP_INTERVAL': 10,
    'MAX_FLOWS': 10000, 'COLORS': {
        'RESET': '\033[0m', 'RED': '\033[91m', 'GREEN': '\033[92m', 'YELLOW': '\033[93m',
        'BLUE': '\033[94m', 'PURPLE': '\033[95m', 'CYAN': '\033[96m', 'WHITE': '\033[97m',
        'BOLD': '\033[1m', 'UNDERLINE': '\033[4m'
    }
}

class FlowRecord:
    """Almacena y analiza información de flujos de red"""
    
    __slots__ = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packets',
                'start_time', 'last_update', 'creation_time', 'fwd_packets', 'bwd_packets',
                'packet_lengths', 'packet_times', 'last_packet_time', 'flow_duration',
                'inter_arrival_times', 'fwd_inter_arrival_times', 'bwd_inter_arrival_times',
                'flags', 'is_scan_suspect', 'connection_attempts', 'failed_connections',
                'http_methods', 'http_status_codes', 'http_payloads', 'web_traffic',
                'payload_entropy', 'connection_state', 'retransmissions', 'out_of_order',
                'ports_seen', 'periodic_behavior']
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Datos básicos del flujo
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = src_port, dst_port
        self.protocol = protocol
        self.packets, self.fwd_packets, self.bwd_packets = [], [], []
        self.start_time, self.last_update = None, time.time()
        self.creation_time = time.time()
        
        # Métricas de tiempo y tamaño
        self.packet_lengths, self.packet_times = [], []
        self.last_packet_time = None
        self.flow_duration = 0
        self.inter_arrival_times = []
        self.fwd_inter_arrival_times, self.bwd_inter_arrival_times = [], []
        
        # Banderas TCP y estado
        self.flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0}
        self.connection_state = "UNKNOWN"
        
        # Detección de anomalías
        self.is_scan_suspect = False
        self.connection_attempts = self.failed_connections = 0
        self.ports_seen = set()
        self.retransmissions = self.out_of_order = 0
        self.periodic_behavior = 0
        
        # Detección web
        self.web_traffic = False
        self.http_methods = Counter()
        self.http_status_codes = Counter()
        self.http_payloads = []
        self.payload_entropy = 0
    
    def add_packet(self, packet, timestamp):
        """Añade un paquete al flujo y actualiza estadísticas"""
        try:
            # Inicializar tiempo de inicio
            if not self.start_time:
                self.start_time = timestamp
            
            # Calcular tiempos entre llegadas
            if self.last_packet_time:
                iat = timestamp - self.last_packet_time
                self.inter_arrival_times.append(iat)
                
                # Análisis de periodicidad
                if len(self.inter_arrival_times) > 5:
                    iat_std, iat_mean = np.std(self.inter_arrival_times[-5:]), np.mean(self.inter_arrival_times[-5:])
                    if iat_mean > 0 and iat_std < 0.1 * iat_mean:
                        self.periodic_behavior += 1
            
            self.last_packet_time = timestamp
            self.flow_duration = timestamp - self.start_time
            self.last_update = time.time()
            
            # Guardar paquete
            self.packet_times.append(timestamp)
            self.packets.append(packet)
            
            # Extraer longitud del paquete de forma segura
            packet_len = 0
            if hasattr(packet, 'length'):
                try:
                    packet_len = int(packet.length)
                except (ValueError, TypeError):
                    packet_len = len(self.packets) > 0 and np.mean(self.packet_lengths) or 64
            
            self.packet_lengths.append(packet_len)
            
            # Determinar dirección del paquete
            is_forward = hasattr(packet, 'ip') and packet.ip.src == self.src_ip and packet.ip.dst == self.dst_ip
            
            # Actualizar métricas de dirección
            if is_forward:
                self.fwd_packets.append(packet_len)
                if len(self.fwd_packets) > 1 and self.inter_arrival_times:
                    self.fwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            else:
                self.bwd_packets.append(packet_len)
                if len(self.bwd_packets) > 1 and self.inter_arrival_times:
                    self.bwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            
            # Procesar TCP
            if hasattr(packet, 'tcp'):
                self._process_tcp(packet)
        except Exception:
            pass
    
    def _process_tcp(self, packet):
        """Procesa la información específica de TCP"""
        # Procesar banderas
        for flag in self.flags:
            self._update_flag(packet, flag.lower())
        
        # Analizar estado de conexión
        if self.flags['SYN'] > 0 and self.flags['ACK'] == 0:
            self.connection_state, self.connection_attempts = "SYN_SENT", self.connection_attempts + 1
        elif self.flags['SYN'] > 0 and self.flags['ACK'] > 0:
            self.connection_state = "ESTABLISHED"
        elif self.flags['FIN'] > 0:
            self.connection_state = "FIN_WAIT"
        elif self.flags['RST'] > 0:
            self.connection_state, self.failed_connections = "CLOSED", self.failed_connections + 1
        
        # Detectar retransmisiones y paquetes fuera de orden
        self.retransmissions += 1 if hasattr(packet.tcp, 'analysis_retransmission') else 0
        self.out_of_order += 1 if hasattr(packet.tcp, 'analysis_out_of_order') else 0
        
        # Procesar puerto destino para detección de escaneo
        if hasattr(packet.tcp, 'dstport'):
            try:
                port_val = getattr(packet.tcp, 'dstport')
                if isinstance(port_val, int) or (isinstance(port_val, str) and port_val.isdigit()):
                    self.ports_seen.add(int(port_val) if isinstance(port_val, str) else port_val)
            except: pass
        
        # Detectar tráfico web
        src_port = self._safe_port_parse(packet.tcp, 'srcport')
        dst_port = self._safe_port_parse(packet.tcp, 'dstport')
        
        if src_port in CONFIG['WEB_PORTS'] or dst_port in CONFIG['WEB_PORTS']:
            self.web_traffic = True
            self._process_http(packet)
        
        # Actualizar estadísticas de escaneo
        if len(self.ports_seen) >= CONFIG['PORT_SCAN_THRESHOLD'] and self.flow_duration <= CONFIG['PORT_SCAN_TIME_WINDOW']:
            self.is_scan_suspect = True
    
    def _update_flag(self, packet, flag_name):
        """Actualiza de forma segura una bandera TCP"""
        if not hasattr(packet.tcp, flag_name):
            return
            
        try:
            flag_value = getattr(packet.tcp, flag_name)
            if isinstance(flag_value, bool) and flag_value:
                self.flags[flag_name.upper()] += 1
            elif isinstance(flag_value, (int, float)) and flag_value > 0:
                self.flags[flag_name.upper()] += 1
            elif isinstance(flag_value, str):
                if flag_value.isdigit() and int(flag_value) > 0:
                    self.flags[flag_name.upper()] += 1
                elif flag_value.lower() in ('true', 'yes', '1'):
                    self.flags[flag_name.upper()] += 1
        except: pass
    
    def _safe_port_parse(self, obj, attr_name):
        """Extrae de forma segura un puerto de un objeto"""
        try:
            if hasattr(obj, attr_name):
                val = getattr(obj, attr_name)
                if isinstance(val, int):
                    return val
                elif isinstance(val, str) and val.isdigit():
                    return int(val)
        except: pass
        return 0
    
    def _process_http(self, packet):
        """Procesa información HTTP si está disponible"""
        if not hasattr(packet, 'http'):
            return
            
        if hasattr(packet.http, 'request_method'):
            self.http_methods[packet.http.request_method] += 1
            
        if hasattr(packet.http, 'response_code'):
            self.http_status_codes[packet.http.response_code] += 1
            
        if hasattr(packet.http, 'file_data'):
            try:
                self.http_payloads.append(packet.http.file_data)
                self.payload_entropy = max(self.payload_entropy, self._calculate_entropy(packet.http.file_data))
            except: pass
    
    def _calculate_entropy(self, data):
        """Calcula la entropía de Shannon de los datos"""
        if not data:
            return 0
        try:
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            freq = Counter(data_bytes)
            return -sum(count/len(data_bytes) * np.log2(count/len(data_bytes)) for count in freq.values()) / 8.0
        except:
            return 0
    
    def get_features(self):
        """Extrae características para el modelo de detección"""
        # Evitar divisiones por cero
        n_packets = max(1, len(self.packets))
        flow_duration = max(0.001, self.flow_duration)
        
        # Calcular estadísticas básicas
        total_fwd_packets = len(self.fwd_packets)
        total_bwd_packets = len(self.bwd_packets)
        total_fwd_length = sum(self.fwd_packets)
        total_bwd_length = sum(self.bwd_packets)
        
        # Estadísticas de paquetes
        has_packets = len(self.packet_lengths) > 0
        packet_length_mean = np.mean(self.packet_lengths) if has_packets else 0
        packet_length_std = np.std(self.packet_lengths) if has_packets and len(self.packet_lengths) > 1 else 0
        packet_length_variance = np.var(self.packet_lengths) if has_packets and len(self.packet_lengths) > 1 else 0
        
        # Promedios de segmentos
        avg_fwd_segment_size = np.mean(self.fwd_packets) if self.fwd_packets else 0
        avg_bwd_segment_size = np.mean(self.bwd_packets) if self.bwd_packets else 0
        
        # Tasas de flujo
        flow_bytes_per_sec = (total_fwd_length + total_bwd_length) / flow_duration
        flow_packets_per_sec = n_packets / flow_duration
        
        # Tiempos entre llegadas
        flow_iat_mean = np.mean(self.inter_arrival_times) if self.inter_arrival_times else 0
        flow_iat_std = np.std(self.inter_arrival_times) if len(self.inter_arrival_times) > 1 else 0
        fwd_iat_mean = np.mean(self.fwd_inter_arrival_times) if self.fwd_inter_arrival_times else 0
        bwd_iat_mean = np.mean(self.bwd_inter_arrival_times) if self.bwd_inter_arrival_times else 0
        
        # Retornar diccionario de características
        return {
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
            'subflow_fwd_packets': total_fwd_packets,
            'subflow_fwd_bytes': total_fwd_length,
            'subflow_bwd_packets': total_bwd_packets,
            'subflow_bwd_bytes': total_bwd_length
        }
    
    def calculate_threat_scores(self):
        """Calcula puntuaciones de amenaza para diferentes tipos de ataque"""
        # Puntuación de escaneo de puertos
        scan_score = min(1.0, 
            0.4 * min(len(self.ports_seen) / CONFIG['PORT_SCAN_THRESHOLD'], 1.0) + 
            0.3 * (1.0 - min(self.flags['ACK'], self.flags['SYN']) / max(1, self.flags['SYN'])) +
            0.3 * min(self.failed_connections / max(1, self.connection_attempts), 1.0) +
            0.2 * (self.flow_duration < 5.0 and len(self.ports_seen) > 3) +
            0.1 * (self.inter_arrival_times and np.mean(self.inter_arrival_times) < 0.1)
        )
        
        # Puntuación de ataque web
        web_score = 0.0
        if self.web_traffic:
            suspicious_methods = {'OPTIONS', 'TRACE', 'CONNECT', 'DELETE', 'PUT'}
            web_score = min(1.0,
                0.2 * sum(1 for m in suspicious_methods if m in self.http_methods) +
                0.3 * (self.payload_entropy > CONFIG['ENTROPY_THRESHOLD']) +
                0.15 * sum(1 for c in {'400', '401', '403', '500', '501', '502', '503'} if c in self.http_status_codes) +
                self._check_suspicious_patterns() * 0.25
            )
        
        # Puntuación de DoS
        packets_per_sec = len(self.packet_lengths) / max(0.1, self.flow_duration)
        dos_score = min(1.0,
            0.2 * min(packets_per_sec / CONFIG['MAX_PACKETS_PER_SEC'], 5.0) * (packets_per_sec > CONFIG['MAX_PACKETS_PER_SEC']) + 
            0.4 * (self.flags['SYN'] > 10 and self.flags['SYN'] > self.flags['ACK'] * 2) +
            0.2 * min(self.retransmissions / 20.0, 1.0) * (self.retransmissions > 5) +
            0.2 * (np.mean(self.packet_lengths) < 100 and len(self.packet_lengths) > 50) +
            0.2 * (np.std(self.packet_lengths) < 5 and len(self.packet_lengths) > 10)
        )
        
        return {'scan': scan_score, 'web': web_score, 'dos': dos_score}
    
    def _check_suspicious_patterns(self):
        """Busca patrones sospechosos en payloads HTTP"""
        suspicious_patterns = ["script", "alert(", "SELECT", "UNION", "INSERT", 
            "DELETE FROM", "DROP TABLE", "<script>", "eval(", "'--", "' OR 1=1"]
            
        for payload in self.http_payloads:
            payload_str = payload.decode('utf-8', 'ignore').lower() if isinstance(payload, bytes) else str(payload).lower()
            if any(pattern.lower() in payload_str for pattern in suspicious_patterns):
                return 1.0
        return 0.0


class NetworkMonitor:
    """Monitor de red para detección de intrusiones"""
    
    def __init__(self, model_path, interface='eth0', timeout=60):
        self.model_path, self.interface, self.timeout = model_path, interface, timeout
        self.flows = {}
        self.flow_lock = threading.Lock()
        self.stop_capture = threading.Event()
        self.threads = {}
        
        # Cargar modelo
        try:
            logger.info(f"Cargando modelo desde {model_path}")
            model_data = joblib.load(model_path)
            self.model, self.scaler = model_data['model'], model_data['scaler']
            self.selected_features = model_data['selected_features']
            logger.info(f"Modelo cargado con {len(self.selected_features)} características")
        except Exception as e:
            logger.error(f"Error cargando modelo: {e}")
            raise
        
        # Contadores y almacenamiento
        self.alert_counts = {'normal': 0, 'suspicious': 0, 'attack': 0}
        self.attack_types = {'scan': 0, 'dos': 0, 'web': 0, 'other': 0}
        self.recent_detections = deque(maxlen=200)
        self.thresholds = {'normal': CONFIG['NORMAL_THRESHOLD'], 'suspicious': CONFIG['SUSPICIOUS_THRESHOLD']}
        self.connection_tracker = defaultdict(lambda: {'ports': set(), 'last_update': time.time(), 
                                                      'connections': 0, 'failed': 0, 'scan_score': 0})
        
        # Reputación de IPs
        self.ip_reputation_cache = {}
        self.malicious_networks = [ipaddress.ip_network(net) for net in 
                                  ['185.156.73.0/24', '91.219.236.0/24'] if self._valid_network(net)]
        
        # Métricas de rendimiento
        self.performance = {
            'start_time': time.time(),
            'packets_processed': 0,
            'flows_analyzed': 0,
            'processing_times': deque(maxlen=100)
        }
    
    def _valid_network(self, net):
        """Valida una red IP"""
        try:
            ipaddress.ip_network(net)
            return True
        except:
            return False
    
    def start_capture(self):
        """Inicia la captura de paquetes"""
        if any(t and t.is_alive() for t in self.threads.values()):
            logger.warning("La captura ya está en ejecución")
            return
            
        self.stop_capture.clear()
        self.threads = {
            'capture': threading.Thread(target=self._capture_packets),
            'cleanup': threading.Thread(target=self._cleanup_flows),
            'stats': threading.Thread(target=self._print_stats)
        }
        
        # Registrar handler para SIGINT
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Iniciar hilos
        logger.info(f"Iniciando captura en interfaz {self.interface}")
        print(f"{CONFIG['COLORS']['BOLD']}Sistema de Detección de Intrusiones iniciado en {self.interface}{CONFIG['COLORS']['RESET']}")
        print(f"Presione Ctrl+C para detener la captura\n")
        
        for thread in self.threads.values():
            thread.daemon = True
            thread.start()
    
    def _signal_handler(self, sig, frame):
        """Maneja la señal de interrupción"""
        print("\nDeteniendo captura...")
        self.stop_capture_thread()
        print("\nEstadísticas finales:")
        self._print_final_stats()
        sys.exit(0)
    
    def stop_capture_thread(self):
        """Detiene todos los hilos de captura"""
        logger.info("Deteniendo captura")
        self.stop_capture.set()
        
        for name, thread in self.threads.items():
            if thread and thread.is_alive():
                thread.join(timeout=2.0)
    
    def _capture_packets(self):
        """Captura y procesa paquetes de red"""
        try:
            # Intentar configurar event loop asíncrono
            try:
                import asyncio
                asyncio.set_event_loop(asyncio.new_event_loop())
            except: pass
            
            # Configurar captura con filtro óptimo
            try:
                capture = pyshark.LiveCapture(interface=self.interface, bpf_filter='tcp or udp')
            except:
                capture = pyshark.LiveCapture(interface=self.interface)
                
            logger.info(f"Captura iniciada en {self.interface}")
            
            # Capturar paquetes continuamente
            for packet in capture.sniff_continuously():
                if self.stop_capture.is_set():
                    break
                    
                try:
                    start_time = time.time()
                    self._process_packet(packet)
                    self.performance['packets_processed'] += 1
                    self.performance['processing_times'].append(time.time() - start_time)
                except Exception as e:
                    pass
                    
        except Exception as e:
            logger.error(f"Error en captura: {e}")
            print(f"{CONFIG['COLORS']['RED']}Error en captura: {e}{CONFIG['COLORS']['RESET']}")
    
    def _process_packet(self, packet):
        """Procesa un paquete y lo añade al flujo correspondiente"""
        # Verificar si es un paquete IP
        if not hasattr(packet, 'ip'):
            return
            
        # Extraer información básica
        src_ip, dst_ip = packet.ip.src, packet.ip.dst
        src_port = dst_port = '0'
        protocol = packet.ip.proto
        
        # Obtener puertos y protocolo
        try:
            if hasattr(packet, 'tcp'):
                src_port, dst_port, protocol = packet.tcp.srcport, packet.tcp.dstport, 'TCP'
            elif hasattr(packet, 'udp'):
                src_port, dst_port, protocol = packet.udp.srcport, packet.udp.dstport, 'UDP'
        except: pass
        
        # Crear identificador normalizado (el menor IP/puerto primero)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
        # Actualizar tracker de conexiones para escaneos
        if protocol == 'TCP':
            try:
                dst_port_int = int(dst_port) if isinstance(dst_port, str) and dst_port.isdigit() else 0
                if dst_port_int > 0:
                    self._update_scan_tracker(src_ip, dst_port_int, packet)
            except: pass
        
        # Añadir paquete al flujo
        with self.flow_lock:
            # Verificar si se necesita limpieza de flujos
            if len(self.flows) >= CONFIG['MAX_FLOWS']:
                old_flows = sorted(self.flows.items(), key=lambda x: x[1].last_update)[:int(CONFIG['MAX_FLOWS'] * 0.1)]
                for flow_id, _ in old_flows:
                    del self.flows[flow_id]
            
            # Crear flujo si no existe
            if flow_id not in self.flows:
                self.flows[flow_id] = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Añadir paquete con timestamp
            try:
                timestamp = float(packet.sniff_timestamp)
            except:
                timestamp = time.time()
                
            self.flows[flow_id].add_packet(packet, timestamp)
            
            # Evaluar flujo si tiene suficientes paquetes
            if len(self.flows[flow_id].packets) >= CONFIG['MIN_PACKETS_TO_ANALYZE']:
                self._evaluate_flow(flow_id)
    
    def _update_scan_tracker(self, src_ip, dst_port, packet):
        """Actualiza el rastreador de conexiones para detección de escaneo"""
        # Añadir puerto al conjunto
        self.connection_tracker[src_ip]['ports'].add(dst_port)
        self.connection_tracker[src_ip]['last_update'] = time.time()
        
        # Contar intentos de conexión y fallos
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
            try:
                if hasattr(packet.tcp, 'flags_syn') and getattr(packet.tcp, 'flags_syn') in (1, '1', True):
                    self.connection_tracker[src_ip]['connections'] += 1
                if hasattr(packet.tcp, 'flags_reset') and getattr(packet.tcp, 'flags_reset') in (1, '1', True):
                    self.connection_tracker[src_ip]['failed'] += 1
            except: pass
        
        # Calcular puntuación de escaneo
        port_count = len(self.connection_tracker[src_ip]['ports'])
        if port_count >= CONFIG['PORT_SCAN_THRESHOLD']:
            failed_ratio = self.connection_tracker[src_ip]['failed'] / max(1, self.connection_tracker[src_ip]['connections'])
            time_factor = CONFIG['PORT_SCAN_TIME_WINDOW'] / max(1, time.time() - self.connection_tracker[src_ip]['last_update'])
            
            self.connection_tracker[src_ip]['scan_score'] = min(
                0.6 * min(port_count / 20, 1.0) + 0.3 * failed_ratio + 0.1 * time_factor, 
                1.0
            )
    
    def _cleanup_flows(self):
        """Limpia flujos inactivos periódicamente"""
        while not self.stop_capture.is_set():
            time.sleep(CONFIG['CLEANUP_INTERVAL'])
            
            current_time = time.time()
            expired_flows = []
            
            with self.flow_lock:
                for flow_id, flow in self.flows.items():
                    if current_time - flow.last_update > self.timeout:
                        expired_flows.append(flow_id)
                        if len(flow.packets) >= CONFIG['MIN_PACKETS_TO_ANALYZE']:
                            self._evaluate_flow(flow_id)
                
                for flow_id in expired_flows:
                    del self.flows[flow_id]
            
            # Limpiar trackers de conexiones antiguos
            expired_trackers = [ip for ip, data in self.connection_tracker.items() 
                              if current_time - data['last_update'] > self.timeout * 2]
            for ip in expired_trackers:
                del self.connection_tracker[ip]
            
            # Limpiar caché de reputación IP si es muy grande
            if len(self.ip_reputation_cache) > 10000:
                self.ip_reputation_cache = {}
    
    def _evaluate_flow(self, flow_id):
        """Evalúa un flujo para detectar posibles intrusiones"""
        try:
            start_time = time.time()
            flow = self.flows[flow_id]
            
            # Obtener características para el modelo
            features = flow.get_features()
            
            # Verificar características faltantes
            missing_features = [f for f in self.selected_features if f not in features]
            if missing_features:
                return
            
            # Preparar datos para el modelo
            X = np.array([[features[f] for f in self.selected_features]])
            X_scaled = self.scaler.transform(X)
            
            # Obtener predicción del modelo ML
            y_proba = self.model.predict_proba(X_scaled)[0, 1]  # Probabilidad de ataque
            
            # Obtener puntuaciones por tipo de ataque
            scores = flow.calculate_threat_scores()
            
            # Determinar tipo de ataque principal
            attack_score = max(scores.values())
            attack_type = max(scores.items(), key=lambda x: x[1])[0] if attack_score > 0.6 else "other"
            
            # Verificar reputación IP
            src_rep = self.check_ip_reputation(flow.src_ip)
            dst_rep = self.check_ip_reputation(flow.dst_ip)
            rep_score = max(src_rep, dst_rep)
            
            # Calcular puntuación final combinada
            enhanced_score = min(
                0.5 * y_proba + 0.3 * attack_score + 0.2 * rep_score,
                1.0
            )
            
            # Clasificar según umbrales
            if enhanced_score < self.thresholds['normal']:
                status, level = 'normal', 'info'
            elif enhanced_score < self.thresholds['suspicious']:
                status, level = 'suspicious', 'warning'
            else:
                status, level = 'attack', 'error'
                self.attack_types[attack_type] += 1
            
            # Actualizar contadores
            self.alert_counts[status] += 1
            self.performance['flows_analyzed'] += 1
            
            # Crear mensaje y registrar
            msg = f"[{status.upper()}] {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} ({flow.protocol}) - Prob: {enhanced_score:.4f}"
            if status == 'attack':
                msg += f" - Tipo: {attack_type.upper()}"
                if attack_type == "scan":
                    msg += f" - Puertos: {len(flow.ports_seen)}"
            
            # Registrar según nivel
            getattr(logger, level)(msg)
            
            # Mostrar en consola si corresponde
            if status != 'normal' or CONFIG['SHOW_NORMAL_TRAFFIC']:
                self._print_detection(status, flow, enhanced_score, attack_type)
            
            # Guardar detección
            self.recent_detections.append({
                'timestamp': datetime.datetime.now(),
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'status': status,
                'attack_type': attack_type if status == 'attack' else None,
                'probability': enhanced_score,
                'packet_count': len(flow.packets),
                'flags': flow.flags.copy(),
                'ports_accessed': list(flow.ports_seen)
            })
            
            # Eliminar flujo si es ataque grave
            if status == 'attack' and enhanced_score > 0.8:
                del self.flows[flow_id]
                
        except Exception as e:
            pass  # Ignorar errores en el proceso de evaluación
    
    def check_ip_reputation(self, ip):
        """Verifica la reputación de una IP con caché"""
        # Usar caché si existe
        if ip in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip]
        
        try:
            # Verificar si es IP válida
            ip_obj = ipaddress.ip_address(ip)
            
            # Verificar redes maliciosas conocidas
            score = next((0.8 for net in self.malicious_networks if ip_obj in net), 0.0)
            
            # IPs privadas, reservadas o multicast son neutrales
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_multicast:
                score = 0.0
                
            # Guardar en caché y retornar
            self.ip_reputation_cache[ip] = score
            return score
        except:
            # En caso de error, usar valor neutral
            self.ip_reputation_cache[ip] = 0.0
            return 0.0
    
    def _print_detection(self, status, flow, probability, attack_type=None):
        """Imprime detección formateada en consola"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Seleccionar color según tipo
        if status == 'normal':
            color, prefix = CONFIG['COLORS']['GREEN'], "[NORMAL]"
        elif status == 'suspicious':
            color, prefix = CONFIG['COLORS']['YELLOW'], "[SOSPECHOSO]"
        else:
            color, prefix = CONFIG['COLORS']['RED'], f"[ATAQUE-{attack_type.upper()}]"
        
        # Crear mensaje
        message = f"{color}{timestamp} {prefix} {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} ({flow.protocol}) - Prob: {probability:.4f}{CONFIG['COLORS']['RESET']}"
        
        # Añadir detalle según tipo
        if status == 'attack':
            if attack_type == 'scan':
                message += f" - Puertos escaneados: {len(flow.ports_seen)}"
            elif attack_type == 'web':
                message += f" - Métodos: {dict(flow.http_methods)}"
        
        print(message)
    
    def _print_stats(self):
        """Imprime estadísticas periódicamente"""
        last_packet_count = 0
        last_time = time.time()
        
        while not self.stop_capture.is_set():
            try:
                # Calcular tasas
                current_time = time.time()
                time_diff = max(0.001, current_time - last_time)
                
                packets_diff = self.performance['packets_processed'] - last_packet_count
                packet_rate = packets_diff / time_diff
                
                last_packet_count = self.performance['packets_processed']
                last_time = current_time
                
                # Limpiar pantalla
                print("\033[2J\033[H", end='')
                
                # Imprimir estadísticas
                print(f"{CONFIG['COLORS']['BOLD']}Sistema de Detección de Intrusiones - Estadísticas{CONFIG['COLORS']['RESET']}")
                print(f"Interfaz: {self.interface}")
                print(f"Tiempo: {self._format_duration(current_time - self.performance['start_time'])}")
                print(f"Umbrales - Normal: {self.thresholds['normal']}, Sospechoso: {self.thresholds['suspicious']}")
                print("-" * 80)
                
                # Flujos y paquetes
                with self.flow_lock:
                    active_flows = len(self.flows)
                
                print(f"Flujos activos: {active_flows}")
                print(f"Paquetes procesados: {self.performance['packets_processed']} ({packet_rate:.1f} pkt/s)")
                print(f"Flujos analizados: {self.performance['flows_analyzed']}")
                
                if self.performance['processing_times']:
                    avg_time = sum(self.performance['processing_times']) / len(self.performance['processing_times']) * 1000
                    print(f"Tiempo promedio: {avg_time:.2f} ms/pkt")
                
                # Distribución de alertas
                total = sum(self.alert_counts.values())
                if total > 0:
                    c = CONFIG['COLORS']
                    print("\nDistribución de alertas:")
                    print(f"{c['GREEN']}Normal: {self.alert_counts['normal']} ({self.alert_counts['normal']/total*100:.1f}%){c['RESET']}")
                    print(f"{c['YELLOW']}Sospechoso: {self.alert_counts['suspicious']} ({self.alert_counts['suspicious']/total*100:.1f}%){c['RESET']}")
                    print(f"{c['RED']}Ataque: {self.alert_counts['attack']} ({self.alert_counts['attack']/total*100:.1f}%){c['RESET']}")
                
                # Tipos de ataques
                if self.alert_counts['attack'] > 0:
                    print("\nTipos de ataques detectados:")
                    for attack_type, count in self.attack_types.items():
                        if count > 0:
                            color = CONFIG['COLORS']['RED'] if attack_type in ['scan', 'dos'] else CONFIG['COLORS']['PURPLE']
                            print(f"{color}{attack_type}: {count}{CONFIG['COLORS']['RESET']}")
                
                # IPs sospechosas
                suspicious_ips = Counter(d['src_ip'] for d in self.recent_detections if d['status'] in ['suspicious', 'attack'])
                if suspicious_ips:
                    print("\nTop 5 IPs sospechosas:")
                    for ip, count in suspicious_ips.most_common(5):
                        print(f"{ip}: {count} detecciones")
                
                # Actividad reciente
                print("\nActividad reciente:")
                recent = list(self.recent_detections)[-5:]
                if recent:
                    for d in reversed(recent):
                        ts = d['timestamp'].strftime('%H:%M:%S')
                        color = CONFIG['COLORS']['GREEN' if d['status'] == 'normal' else 'YELLOW' if d['status'] == 'suspicious' else 'RED']
                        print(f"{color}[{ts}] {d['src_ip']} -> {d['dst_ip']} ({d['protocol']}) - {d['probability']:.4f}{CONFIG['COLORS']['RESET']}")
                else:
                    print("No hay actividad reciente.")
                
                print("\nPresione Ctrl+C para detener la captura")
                
                # Esperar antes de actualizar
                time.sleep(CONFIG['UPDATE_INTERVAL'])
                
            except Exception as e:
                pass
    
    def _print_final_stats(self):
        """Imprime estadísticas finales al terminar"""
        try:
            runtime = time.time() - self.performance['start_time']
            
            print(f"\n{CONFIG['COLORS']['BOLD']}Estadísticas finales:{CONFIG['COLORS']['RESET']}")
            print(f"Duración total: {self._format_duration(runtime)}")
            print(f"Paquetes procesados: {self.performance['packets_processed']}")
            print(f"Flujos analizados: {self.performance['flows_analyzed']}")
            print(f"Tasa: {self.performance['packets_processed']/runtime:.2f} pkt/s")
            
            if self.performance['processing_times']:
                avg_proc = sum(self.performance['processing_times']) / len(self.performance['processing_times']) * 1000
                print(f"Tiempo promedio: {avg_proc:.2f} ms/pkt")
            
            # Distribución de alertas
            total = sum(self.alert_counts.values())
            if total > 0:
                c = CONFIG['COLORS']
                print(f"\nDistribución de {total} alertas:")
                print(f"{c['GREEN']}Normal: {self.alert_counts['normal']} ({self.alert_counts['normal']/total*100:.1f}%){c['RESET']}")
                print(f"{c['YELLOW']}Sospechoso: {self.alert_counts['suspicious']} ({self.alert_counts['suspicious']/total*100:.1f}%){c['RESET']}")
                print(f"{c['RED']}Ataque: {self.alert_counts['attack']} ({self.alert_counts['attack']/total*100:.1f}%){c['RESET']}")
            
            # Tipos de ataques
            if self.alert_counts['attack'] > 0:
                print("\nTipos de ataques detectados:")
                for attack_type, count in self.attack_types.items():
                    if count > 0:
                        print(f"{attack_type}: {count}")
            
            # Top IPs sospechosas
            suspicious_ips = Counter(d['src_ip'] for d in self.recent_detections if d['status'] in ['suspicious', 'attack'])
            if suspicious_ips:
                print("\nTop 5 IPs sospechosas:")
                for ip, count in suspicious_ips.most_common(5):
                    print(f"{ip}: {count} detecciones")
            
            print(f"\nLogs completos disponibles en: ids_detection.log")
        except Exception:
            pass
    
    def _format_duration(self, seconds):
        """Formatea una duración en segundos como HH:MM:SS"""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02}:{minutes:02}:{seconds:02}"
    
    def export_stats(self, filename=None):
        """Exporta estadísticas a un archivo JSON"""
        if not filename:
            filename = f"ids_stats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Preparar estadísticas para exportar
        stats = {
            'timestamp': datetime.datetime.now().isoformat(),
            'runtime': time.time() - self.performance['start_time'],
            'active_flows': len(self.flows),
            'packets_processed': self.performance['packets_processed'],
            'flows_analyzed': self.performance['flows_analyzed'],
            'alert_counts': self.alert_counts,
            'attack_types': self.attack_types
        }
        
        # Convertir detecciones recientes
        stats['recent_detections'] = []
        for detection in self.recent_detections:
            d = detection.copy()
            d['timestamp'] = d['timestamp'].isoformat()
            d['ports_accessed'] = list(d['ports_accessed']) if isinstance(d['ports_accessed'], set) else d['ports_accessed']
            stats['recent_detections'].append(d)
        
        # Exportar a JSON
        try:
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"Estadísticas exportadas a {filename}")
            return True
        except Exception as e:
            logger.error(f"Error exportando estadísticas: {e}")
            return False


def run_ids(model_path, interface, duration=0, options=None):
    """Ejecuta el sistema de detección de intrusiones"""
    print(f"{CONFIG['COLORS']['BOLD']}Iniciando monitoreo en interfaz {interface}{CONFIG['COLORS']['RESET']}")
    if duration:
        print(f"Duración programada: {duration} segundos")
    print(f"Umbrales - Normal: {CONFIG['NORMAL_THRESHOLD']}, Sospechoso: {CONFIG['SUSPICIOUS_THRESHOLD']}")
    
    try:
        # Actualizar configuración desde opciones
        if options:
            CONFIG.update({k: v for k, v in options.items() if k in CONFIG})
        
        # Inicializar monitor
        monitor = NetworkMonitor(model_path=model_path, interface=interface)
        
        # Iniciar captura
        monitor.start_capture()
        
        # Ejecutar por duración especificada o hasta interrupción
        if duration:
            try:
                time.sleep(duration)
                monitor.stop_capture_thread()
                monitor._print_final_stats()
                
                # Exportar estadísticas si se solicitó
                if options and options.get('export_stats'):
                    monitor.export_stats()
                    
            except KeyboardInterrupt:
                print("\nInterrumpido por el usuario")
                monitor.stop_capture_thread()
                monitor._print_final_stats()
        else:
            # Si no hay duración, ejecutar hasta interrupción manual
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
    
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"{CONFIG['COLORS']['RED']}Error: {e}{CONFIG['COLORS']['RESET']}")
        traceback.print_exc()


def main():
    """Función principal"""
    # Habilitar colores en Windows
    if os.name == 'nt':
        os.system('color')
    
    # Configurar argumentos
    parser = argparse.ArgumentParser(description="Sistema Compacto de Detección de Intrusiones")
    parser.add_argument("--model", type=str, default="model/modelo_rf_optimizado.pkl", 
                        help="Ruta al modelo entrenado")
    parser.add_argument("--interface", type=str, default="Wi-Fi" if os.name == 'nt' else "eth0", 
                        help="Interfaz de red a monitorear")
    parser.add_argument("--duration", type=int, default=0, 
                        help="Duración del monitoreo en segundos (0=indefinido)")
    parser.add_argument("--threshold-normal", type=float, default=CONFIG['NORMAL_THRESHOLD'],
                        help=f"Umbral para tráfico normal (default: {CONFIG['NORMAL_THRESHOLD']})")
    parser.add_argument("--threshold-suspicious", type=float, default=CONFIG['SUSPICIOUS_THRESHOLD'],
                        help=f"Umbral para tráfico sospechoso (default: {CONFIG['SUSPICIOUS_THRESHOLD']})")
    parser.add_argument("--show-normal", action="store_true", 
                        help="Mostrar tráfico normal en la salida")
    parser.add_argument("--update-interval", type=int, default=CONFIG['UPDATE_INTERVAL'],
                        help=f"Intervalo de actualización de estadísticas (default: {CONFIG['UPDATE_INTERVAL']})")
    parser.add_argument("--export-stats", action="store_true", 
                        help="Exportar estadísticas a un archivo JSON al finalizar")
    parser.add_argument("--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    # Actualizar configuración
    CONFIG.update({
        'NORMAL_THRESHOLD': args.threshold_normal,
        'SUSPICIOUS_THRESHOLD': args.threshold_suspicious,
        'SHOW_NORMAL_TRAFFIC': args.show_normal,
        'UPDATE_INTERVAL': args.update_interval
    })
    
    # Nivel de log
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Verificar modelo
    if not os.path.exists(args.model):
        print(f"{CONFIG['COLORS']['RED']}Error: No se encontró el modelo en {args.model}{CONFIG['COLORS']['RESET']}")
        return
    
    # Opciones
    options = {'export_stats': args.export_stats, 'verbose': args.verbose}
    
    # Ejecutar sistema
    try:
        run_ids(args.model, args.interface, args.duration, options)
    except KeyboardInterrupt:
        print("\nSistema detenido por el usuario")
    except Exception as e:
        print(f"{CONFIG['COLORS']['RED']}Error: {e}{CONFIG['COLORS']['RESET']}")


if __name__ == "__main__":
    main()