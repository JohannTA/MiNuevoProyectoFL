#!/usr/bin/env python3
"""
Logger especializado para el detector integrado
Captura toda la salida del detector en logs estructurados
"""

import logging
import sys
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

class DetectorLogger:
    """Logger especializado para el detector con múltiples niveles y archivos"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.ensure_log_directory()
        
        # Crear loggers especializados
        self.detector_logger = self.setup_detector_logger()
        self.traffic_logger = self.setup_traffic_logger()
        self.anomaly_logger = self.setup_anomaly_logger()
        self.system_logger = self.setup_system_logger()
        
    def ensure_log_directory(self):
        """Asegura que el directorio de logs existe"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # Crear subdirectorios para diferentes tipos de logs
        subdirs = ['detector', 'traffic', 'anomalies', 'system']
        for subdir in subdirs:
            path = os.path.join(self.log_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def setup_detector_logger(self):
        """Logger principal del detector"""
        logger = logging.getLogger('detector_main')
        logger.setLevel(logging.DEBUG)
        
        # Formato detallado para el detector
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | [DETECTOR] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler para archivo diario del detector
        file_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, 'detector', 'detector.log'),
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Handler para consola (solo INFO y superior)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def setup_traffic_logger(self):
        """Logger para tráfico de red (paquetes normales)"""
        logger = logging.getLogger('detector_traffic')
        logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Archivo rotativo por tamaño para tráfico (puede ser voluminoso)
        file_handler = RotatingFileHandler(
            os.path.join(self.log_dir, 'traffic', 'traffic.log'),
            maxBytes=50*1024*1024,  # 50MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        return logger
    
    def setup_anomaly_logger(self):
        """Logger especializado para anomalías detectadas"""
        logger = logging.getLogger('detector_anomalies')
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s | [ANOMALY] %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Archivo diario para anomalías
        file_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, 'anomalies', 'anomalies.log'),
            when='midnight',
            interval=1,
            backupCount=90,  # Mantener 3 meses
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        
        # También a consola para anomalías importantes
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('[ANOMALY] %(message)s')
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.WARNING)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def setup_system_logger(self):
        """Logger para eventos del sistema (inicio, parada, errores)"""
        logger = logging.getLogger('detector_system')
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s | [SYSTEM] %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, 'system', 'system.log'),
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        return logger
    
    def log_detector_start(self, user_id, device_info, model_path):
        """Log del inicio del detector"""
        self.system_logger.info(f"=== INICIO DETECTOR ===")
        self.system_logger.info(f"Usuario ID: {user_id}")
        self.system_logger.info(f"Dispositivo: {device_info.get('brand')} {device_info.get('model')}")
        self.system_logger.info(f"Modelo: {model_path}")
        self.system_logger.info(f"Timestamp: {datetime.now().isoformat()}")
        
    def log_detector_stop(self, stats):
        """Log del final del detector con estadísticas"""
        self.system_logger.info(f"=== FIN DETECTOR ===")
        self.system_logger.info(f"Tiempo ejecución: {stats.get('runtime', 'N/A')}")
        self.system_logger.info(f"Paquetes procesados: {stats.get('total_packets', 0)}")
        self.system_logger.info(f"Anomalías detectadas: {stats.get('anomalies', 0)}")
        self.system_logger.info(f"Detecciones enviadas: {stats.get('detections_sent', 0)}")
        
    def log_traffic(self, packet_info):
        """Log de tráfico normal (solo para debug)"""
        if packet_info.get('status') == 'NORMAL':
            self.traffic_logger.debug(
                f"{packet_info.get('src_ip')}:{packet_info.get('src_port')} -> "
                f"{packet_info.get('dst_ip')}:{packet_info.get('dst_port')} "
                f"[{packet_info.get('protocol')}] NORMAL"
            )
    
    def log_anomaly(self, anomaly_data):
        """Log de anomalías detectadas"""
        self.anomaly_logger.warning(
            f"DETECTED: {anomaly_data.get('anomaly_type')} | "
            f"Src: {anomaly_data.get('source_ip')}:{anomaly_data.get('source_port')} | "
            f"Dst: {anomaly_data.get('destination_ip')}:{anomaly_data.get('destination_port')} | "
            f"Confidence: {anomaly_data.get('confidence_score', 0):.3f} | "
            f"Severity: {anomaly_data.get('severity')}"
        )
    
    def log_detector_output(self, line):
        """Procesa y categoriza la salida del detector.py"""
        line_clean = line.strip()
        
        if not line_clean:
            return
            
        # Categorizar por contenido
        if 'NORMAL' in line_clean.upper():
            # Tráfico normal - solo debug
            self.detector_logger.debug(f"TRAFFIC: {line_clean}")
        
        elif any(keyword in line_clean.upper() for keyword in ['ANOMALY', 'ATTACK', 'INTRUSION', 'SUSPICIOUS']):
            # Anomalía detectada
            self.detector_logger.warning(f"ANOMALY: {line_clean}")
            
        elif any(keyword in line_clean.upper() for keyword in ['ERROR', 'EXCEPTION', 'FAILED']):
            # Error del detector
            self.detector_logger.error(f"ERROR: {line_clean}")
            
        elif any(keyword in line_clean.upper() for keyword in ['STARTED', 'INITIALIZED', 'LOADING']):
            # Eventos del sistema
            self.detector_logger.info(f"SYSTEM: {line_clean}")
            
        else:
            # Salida general
            self.detector_logger.info(f"OUTPUT: {line_clean}")
    
    def log_detection_sent(self, detection_data):
        """Log de detecciones enviadas al servidor"""
        self.system_logger.info(
            f"SENT: {detection_data.get('anomaly_type')} | "
            f"ID: {detection_data.get('detection_id')} | "
            f"Confidence: {detection_data.get('confidence_score', 0):.3f}"
        )
    
    def log_error(self, error_msg, exception=None):
        """Log de errores del sistema"""
        self.system_logger.error(f"ERROR: {error_msg}")
        if exception:
            self.system_logger.error(f"EXCEPTION: {str(exception)}")
    
    def get_log_stats(self):
        """Obtiene estadísticas de los logs"""
        stats = {}
        
        for log_type in ['detector', 'traffic', 'anomalies', 'system']:
            log_dir = os.path.join(self.log_dir, log_type)
            if os.path.exists(log_dir):
                files = os.listdir(log_dir)
                total_size = sum(
                    os.path.getsize(os.path.join(log_dir, f)) 
                    for f in files if os.path.isfile(os.path.join(log_dir, f))
                )
                stats[log_type] = {
                    'files': len(files),
                    'total_size_mb': round(total_size / (1024*1024), 2)
                }
        
        return stats

# Instancia global del logger especializado
detector_logger = DetectorLogger()