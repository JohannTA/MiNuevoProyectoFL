#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema Avanzado de Detección de Intrusiones (SADI)
--------------------------------------------------
Integra detección basada en ML con patrones de expertos
Autor: Johann
Fecha: 2025-06-03
Versión: 4.0
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
import pyshark
import argparse
import threading
import datetime
import logging
import ipaddress
import json
import sys
import signal
import socket
import re
import traceback
import requests
import warnings
import asyncio
from collections import defaultdict, deque, Counter
from sklearn.preprocessing import StandardScaler
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple, Any, Optional, Union

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore")

# Configuración global
CONFIG = {
    # Umbrales de detección ajustados para reducir falsos positivos
    'NORMAL_THRESHOLD': 0.4,      # Más alto que versiones anteriores
    'SUSPICIOUS_THRESHOLD': 0.7,  # Más alto que versiones anteriores
    
    # Parámetros de detección especializados por tipo de ataque
    'PORT_SCAN': {
        'MIN_PORTS': 10,              # Mínimo de puertos distintos
        'TIME_WINDOW': 5,             # Ventana de tiempo (segundos)
        'SYN_RATIO_THRESHOLD': 0.8,   # % de SYN sin ACK
        'FAILED_CONN_RATIO': 0.5      # % de conexiones fallidas (RST)
    },
    
    'DOS': {
        'PACKET_RATE_THRESHOLD': 100,  # Paquetes por segundo
        'BYTE_RATE_THRESHOLD': 1000000, # Bytes por segundo
        'SYN_FLOOD_THRESHOLD': 50,     # SYNs por segundo
        'ICMP_FLOOD_THRESHOLD': 20,    # ICMPs por segundo
        'SMALL_PACKET_RATIO': 0.9,     # % de paquetes pequeños (<60 bytes)
        'ENTROPY_THRESHOLD': 0.2,      # Baja entropía = tráfico automatizado
    },
    
    'WEB_ATTACK': {
        'SUSPICIOUS_METHODS': {'OPTIONS', 'TRACE', 'CONNECT', 'DELETE', 'PUT'},
        'HTTP_ERROR_RATIO': 0.3,       # % de errores HTTP (4xx, 5xx)
        'PAYLOAD_ENTROPY_HIGH': 0.9,   # Alta entropía = posible ofuscación
        'SQL_INJECTION_PATTERNS': [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"UNION\s+ALL\s+SELECT"
        ],
        'XSS_PATTERNS': [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onload=",
            r"onerror=",
            r"<img[^>]+src[^>]*=",
            r"<iframe[^>]*src[^>]*=",
            r"<body[^>]*background[^>]*="
        ],
        'PATH_TRAVERSAL_PATTERNS': [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"/etc/passwd",
            r"c:\\windows\\system32"
        ],
        'COMMAND_INJECTION_PATTERNS': [
            r";\s*\w+\s*;",
            r"\|\s*\w+",
            r"&&\s*\w+",
            r"`\w+`",
            r"\$\(\w+\)",
            r"system\(",
            r"exec\(",
            r"shell_exec\(",
            r"passthru\(",
            r"eval\("
        ]
    },
    
    'BRUTEFORCE': {
        'LOGIN_ATTEMPT_THRESHOLD': 5,  # Intentos en ventana de tiempo
        'TIME_WINDOW': 60,             # Ventana de tiempo (segundos)
        'FAILED_LOGIN_RATIO': 0.8,     # % de fallos en intentos de login
        'AUTH_FAILURE_PATTERNS': [
            "failed login",
            "authentication fail",
            "invalid password",
            "login incorrect"
        ]
    },
    
    'DATA_EXFILTRATION': {
        'OUTBOUND_DATA_THRESHOLD': 5000000,  # 5MB en una sesión
        'UPLOAD_RATE_THRESHOLD': 500000,     # 500KB por segundo
        'UNUSUAL_PORT_LIST': [1337, 31337, 4444, 8080, 6667, 5353],
        'DNS_QUERY_LENGTH_THRESHOLD': 75,    # DNS exfiltración
        'UNENCRYPTED_SENSITIVE_PATTERNS': [
            r"\b(?:\d[ -]*?){13,16}\b",      # Tarjetas de crédito
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Emails
            r"\b(?:[0-9]{3}-?){2}[0-9]{4}\b",  # SSN (USA)
        ]
    },
    
    'MALWARE_TRAFFIC': {
        'PERIODIC_BEACONING_THRESHOLD': 0.05,  # Variación en tiempos
        'DOMAIN_ENTROPY_THRESHOLD': 0.8,       # Dominios DGA
        'DOMAIN_AGE_THRESHOLD_DAYS': 30,       # Dominios nuevos
        'TLS_INVALID_CERT_THRESHOLD': 3,       # Errores de certificados
        'KNOWN_BAD_JA3_HASHES': set(),         # Se llena dinámicamente
        'ENCRYPTED_WITH_NO_TLS': True,         # Cifrado fuera de TLS
    },
    
    # Configuración de sistema de reputación
    'REPUTATION': {
        'IP_CACHE_SIZE': 10000,
        'DOMAIN_CACHE_SIZE': 1000,
        'IP_MIN_SCORE': 0.3,           # Mínima puntuación para considerar IP maliciosa
        'IP_MAX_AGE_HOURS': 24,        # Tiempo de expiración de reputación
        'REPETITION_PENALTY': 0.1,     # Incremento por repetición de comportamiento
        'TRUSTED_DOMAINS': [           # Dominios confiables (reducir falsos positivos)
            'microsoft.com', 'google.com', 'azure.com', 'github.com', 
            'office.com', 'windowsupdate.com', 'apple.com', 'amazon.com',
            'akamai.net', 'cloudflare.com', 'digicert.com', 'gstatic.com'
        ],
        'TRUSTED_NETWORKS': [         # Redes confiables (formato CIDR)
            '192.168.0.0/16',         # Privadas
            '10.0.0.0/8',             # Privadas
            '172.16.0.0/12',          # Privadas
            '224.0.0.0/4'             # Multicast
        ]
    },
    
    # Límites generales del sistema
    'MAX_FLOWS': 10000,
    'MAX_PACKET_CAPTURE': 100000,
    'CLEANUP_INTERVAL': 30,
    'SOCKET_TIMEOUT': 2.0,
    'MAX_THREADS': 8,
    
    # Colores para terminal
    'COLORS': {
        'RESET': '\033[0m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m'
    },

    # Modos de ejecución
    'SHOW_NORMAL_TRAFFIC': False,
    'LEARNING_MODE': False,
    'LEARNING_DURATION': 300,  # 5 minutos en modo aprendizaje
    'UPDATE_INTERVAL': 5,      # Actualizaciones de estadísticas cada 5 segundos
    'LOG_LEVEL': 'INFO',
}


class DNSCache:
    """Caché para resolver y recordar nombres de dominio"""
    
    def __init__(self, max_size=1000, ttl=3600):
        self.cache = {}
        self.domain_to_ips = {}
        self.max_size = max_size
        self.ttl = ttl  # Tiempo de vida en segundos
        self.lookups = Counter()  # Contar búsquedas por dominio
    
    def get_domain(self, ip):
        """Obtiene el dominio para una IP (con caché)"""
        if ip in self.cache and time.time() - self.cache[ip]['timestamp'] < self.ttl:
            self.lookups[self.cache[ip]['domain']] += 1
            return self.cache[ip]['domain']
        
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self._add_to_cache(ip, domain)
            self.lookups[domain] += 1
            return domain
        except (socket.herror, socket.gaierror):
            # No se pudo resolver, guardar como desconocido
            self._add_to_cache(ip, None)
            return None
    
    def get_ips(self, domain):
        """Obtiene las IPs para un dominio (con caché)"""
        if domain in self.domain_to_ips and time.time() - self.domain_to_ips[domain]['timestamp'] < self.ttl:
            return self.domain_to_ips[domain]['ips']
            
        try:
            # Resolver tanto IPv4 como IPv6
            ips = []
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    result = socket.getaddrinfo(domain, None, family)
                    ips.extend([r[4][0] for r in result])
                except socket.gaierror:
                    pass
            
            # Almacenar en caché
            if ips:
                self.domain_to_ips[domain] = {'ips': ips, 'timestamp': time.time()}
                # Actualizar también la caché inversa
                for ip in ips:
                    self._add_to_cache(ip, domain)
                    
            return ips
        except Exception:
            return []
    
    def _add_to_cache(self, ip, domain):
        """Añade una entrada a la caché con control de tamaño"""
        # Si la caché está llena, eliminar las entradas menos usadas
        if len(self.cache) >= self.max_size:
            # Eliminar el 10% menos usado
            to_remove = int(self.max_size * 0.1)
            for ip_to_remove, _ in sorted(self.cache.items(), 
                                         key=lambda x: self.lookups.get(x[1]['domain'], 0))[:to_remove]:
                del self.cache[ip_to_remove]
        
        # Añadir la nueva entrada
        self.cache[ip] = {'domain': domain, 'timestamp': time.time()}
    
    def calculate_domain_entropy(self, domain):
        """Calcula la entropía de un nombre de dominio (útil para detectar DGA)"""
        if not domain:
            return 0.0
        
        # Calcular entropía solo para el nombre del dominio sin TLD
        parts = domain.split('.')
        if len(parts) > 1:
            domain_name = '.'.join(parts[:-1])  # Excluir TLD
        else:
            domain_name = domain
            
        # Calcular entropía de Shannon
        freq = Counter(domain_name)
        entropy = 0.0
        for count in freq.values():
            p = count / len(domain_name)
            entropy -= p * np.log2(p)
            
        # Normalizar por máxima entropía posible (log2 del alfabeto)
        max_entropy = np.log2(min(26, len(domain_name)))  # Asumimos alfabeto de 26 letras
        if max_entropy > 0:
            return entropy / max_entropy
        return 0.0
    
    def is_domain_suspicious(self, domain):
        """Evalúa si un dominio es sospechoso basado en características"""
        if not domain:
            return False
            
        # Verificar si es un dominio confiable conocido
        for trusted in CONFIG['REPUTATION']['TRUSTED_DOMAINS']:
            if trusted in domain:
                return False
                
        # Calcular entropía (los dominios DGA tienden a tener alta entropía)
        entropy = self.calculate_domain_entropy(domain)
        if entropy > CONFIG['MALWARE_TRAFFIC']['DOMAIN_ENTROPY_THRESHOLD']:
            return True
            
        # Verificar longitud excesiva
        if len(domain) > 50:  # Dominios muy largos son sospechosos
            return True
            
        # Verificar patrones sospechosos (muchos números, consonantes consecutivas)
        digit_ratio = sum(c.isdigit() for c in domain) / max(1, len(domain))
        if digit_ratio > 0.4:  # Más del 40% son dígitos
            return True
            
        # Patrón de muchas consonantes juntas (típico en DGA)
        consonants = "bcdfghjklmnpqrstvwxyz"
        max_consecutive = 0
        current = 0
        
        for c in domain.lower():
            if c in consonants:
                current += 1
                max_consecutive = max(max_consecutive, current)
            else:
                current = 0
                
        if max_consecutive > 5:  # Más de 5 consonantes consecutivas
            return True
            
        return False


class AttackPatterns:
    """Patrones de ataques definidos por expertos"""
    
    @staticmethod
    def check_port_scan(flow) -> float:
        """Verifica patrones de escaneo de puertos"""
        score = 0.0
        port_config = CONFIG['PORT_SCAN']
        
        # Característica 1: Muchos puertos distintos en poco tiempo
        if len(flow.ports_seen) >= port_config['MIN_PORTS']:
            time_factor = min(flow.flow_duration, port_config['TIME_WINDOW']) / port_config['TIME_WINDOW']
            score += 0.6 * (len(flow.ports_seen) / port_config['MIN_PORTS']) * time_factor
        
        # Característica 2: Alto ratio de SYN sin ACK correspondientes
        if flow.flags['SYN'] > 0:
            syn_ack_ratio = 1.0 - min(flow.flags['ACK'], flow.flags['SYN']) / flow.flags['SYN']
            if syn_ack_ratio > port_config['SYN_RATIO_THRESHOLD']:
                score += 0.2 * syn_ack_ratio
        
        # Característica 3: Muchas conexiones fallidas (RST)
        if flow.connection_attempts > 0:
            failed_ratio = min(flow.failed_connections / flow.connection_attempts, 1.0)
            if failed_ratio > port_config['FAILED_CONN_RATIO']:
                score += 0.2 * failed_ratio
        
        # Si todos los scores parciales son positivos, suma bonus por coincidencia de patrón
        if (len(flow.ports_seen) >= port_config['MIN_PORTS'] and 
            flow.flags['SYN'] > 0 and flow.connection_attempts > 0):
            score = min(score + 0.2, 1.0)  # Bonus, limitado a 1.0
        
        return score
    
    @staticmethod
    def check_dos_attack(flow) -> float:
        """Verifica patrones de ataque de denegación de servicio"""
        score = 0.0
        dos_config = CONFIG['DOS']
        
        # Característica 1: Alta tasa de paquetes
        packet_rate = len(flow.packets) / max(0.1, flow.flow_duration)  # paquetes/segundo
        if packet_rate > dos_config['PACKET_RATE_THRESHOLD']:
            score += 0.3 * min(packet_rate / dos_config['PACKET_RATE_THRESHOLD'], 3.0)
        
        # Característica 2: Alta tasa de bytes
        if flow.packet_lengths:
            byte_rate = sum(flow.packet_lengths) / max(0.1, flow.flow_duration)  # bytes/segundo
            if byte_rate > dos_config['BYTE_RATE_THRESHOLD']:
                score += 0.2 * min(byte_rate / dos_config['BYTE_RATE_THRESHOLD'], 2.0)
        
        # Característica 3: SYN Flood (muchos SYN en poco tiempo)
        if flow.flags['SYN'] > 0:
            syn_rate = flow.flags['SYN'] / max(0.1, flow.flow_duration)  # SYN/segundo
            if syn_rate > dos_config['SYN_FLOOD_THRESHOLD']:
                score += 0.2 * min(syn_rate / dos_config['SYN_FLOOD_THRESHOLD'], 2.0)
        
        # Característica 4: Paquetes de tamaño uniforme (típico en ataque automatizado)
        if len(flow.packet_lengths) > 10:
            std_dev = np.std(flow.packet_lengths)
            mean_size = np.mean(flow.packet_lengths)
            if mean_size > 0 and std_dev / mean_size < 0.1:  # Variación menor al 10%
                score += 0.15
        
        # Característica 5: Muchos paquetes pequeños (típico en ciertos DoS)
        if flow.packet_lengths:
            small_packets = sum(1 for size in flow.packet_lengths if size < 60)
            small_ratio = small_packets / len(flow.packet_lengths)
            if small_ratio > dos_config['SMALL_PACKET_RATIO']:
                score += 0.15 * small_ratio
        
        # Característica 6: Comportamiento periódico (baja entropía temporal)
        if len(flow.inter_arrival_times) > 10:
            mean_iat = np.mean(flow.inter_arrival_times)
            std_iat = np.std(flow.inter_arrival_times)
            if mean_iat > 0 and std_iat / mean_iat < dos_config['ENTROPY_THRESHOLD']:
                score += 0.1
        
        # Si múltiples características de DoS están presentes, aplica un bonus
        factors_present = [
            packet_rate > dos_config['PACKET_RATE_THRESHOLD'],
            flow.packet_lengths and sum(flow.packet_lengths) / max(0.1, flow.flow_duration) > dos_config['BYTE_RATE_THRESHOLD'],
            flow.flags['SYN'] > 0 and flow.flags['SYN'] / max(0.1, flow.flow_duration) > dos_config['SYN_FLOOD_THRESHOLD']
        ]
        if sum(factors_present) >= 2:
            score = min(score + 0.2, 1.0)  # Bonus por múltiples indicadores
            
        return score
    
    @staticmethod
    def check_web_attack(flow) -> float:
        """Verifica patrones de ataques web (SQLi, XSS, etc.)"""
        score = 0.0
        web_config = CONFIG['WEB_ATTACK']
        
        # Si no hay tráfico web, retorna 0
        if not flow.web_traffic:
            return 0.0
        
        # Característica 1: Métodos HTTP sospechosos
        for method in web_config['SUSPICIOUS_METHODS']:
            if method in flow.http_methods:
                score += 0.15
                break
        
        # Característica 2: Alta entropía en payload (posible ofuscación)
        if flow.payload_entropy > web_config['PAYLOAD_ENTROPY_HIGH']:
            score += 0.15
        
        # Característica 3: Alto ratio de errores HTTP
        if flow.http_status_codes:
            error_count = sum(flow.http_status_codes[code] for code in flow.http_status_codes 
                             if code.startswith(('4', '5')))
            error_ratio = error_count / sum(flow.http_status_codes.values())
            if error_ratio > web_config['HTTP_ERROR_RATIO']:
                score += 0.15 * min(error_ratio / web_config['HTTP_ERROR_RATIO'], 2.0)
        
        # Característica 4: Patrones de inyección SQL en payloads
        sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in web_config['SQL_INJECTION_PATTERNS']]
        
        # Característica 5: Patrones de XSS en payloads
        xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in web_config['XSS_PATTERNS']]
        
        # Característica 6: Patrones de Path Traversal
        path_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in web_config['PATH_TRAVERSAL_PATTERNS']]
        
        # Característica 7: Patrones de inyección de comandos
        cmd_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in web_config['COMMAND_INJECTION_PATTERNS']]
        
        # Verificar patrones en payloads HTTP
        if flow.http_payloads:
            for payload in flow.http_payloads:
                # Convertir a texto si es necesario
                if isinstance(payload, bytes):
                    payload_str = payload.decode('utf-8', 'ignore')
                else:
                    payload_str = str(payload)
                
                # Verificar SQL Injection
                if any(pattern.search(payload_str) for pattern in sql_patterns):
                    score += 0.3
                
                # Verificar XSS
                if any(pattern.search(payload_str) for pattern in xss_patterns):
                    score += 0.3
                
                # Verificar Path Traversal
                if any(pattern.search(payload_str) for pattern in path_patterns):
                    score += 0.25
                
                # Verificar Command Injection
                if any(pattern.search(payload_str) for pattern in cmd_patterns):
                    score += 0.3
                
                # Limitar a 1.0
                score = min(score, 1.0)
        
        return score
    
    @staticmethod
    def check_bruteforce(flow) -> float:
        """Verifica patrones de ataques de fuerza bruta"""
        score = 0.0
        bf_config = CONFIG['BRUTEFORCE']
        
        # Característica 1: Múltiples intentos en poco tiempo
        if flow.authentication_attempts > bf_config['LOGIN_ATTEMPT_THRESHOLD']:
            time_factor = min(flow.flow_duration, bf_config['TIME_WINDOW']) / bf_config['TIME_WINDOW']
            attempts_factor = min(flow.authentication_attempts / bf_config['LOGIN_ATTEMPT_THRESHOLD'], 3.0)
            score += 0.5 * attempts_factor * time_factor
        
        # Característica 2: Alto ratio de fallos en autenticación
        if flow.authentication_attempts > 0:
            failure_ratio = flow.authentication_failures / flow.authentication_attempts
            if failure_ratio > bf_config['FAILED_LOGIN_RATIO']:
                score += 0.3 * failure_ratio
        
        # Característica 3: Patrones de fallo de autenticación en payloads
        if hasattr(flow, 'http_payloads') and flow.http_payloads:
            for payload in flow.http_payloads:
                if isinstance(payload, bytes):
                    payload_str = payload.decode('utf-8', 'ignore').lower()
                else:
                    payload_str = str(payload).lower()
                
                for pattern in bf_config['AUTH_FAILURE_PATTERNS']:
                    if pattern.lower() in payload_str:
                        score += 0.2
                        break
        
        # Característica 4: Tráfico repetitivo con pequeñas variaciones
        # (típico cuando se prueban diferentes contraseñas)
        if hasattr(flow, 'packet_similarity') and flow.packet_similarity > 0.9:
            score += 0.2
        
        return min(score, 1.0)
    
    @staticmethod
    def check_data_exfiltration(flow) -> float:
        """Verifica patrones de exfiltración de datos"""
        score = 0.0
        exfil_config = CONFIG['DATA_EXFILTRATION']
        
        # Característica 1: Gran volumen de datos salientes
        if flow.src_ip.startswith(('10.', '172.16.', '192.168.')) and hasattr(flow, 'total_bytes_out') and flow.total_bytes_out > exfil_config['OUTBOUND_DATA_THRESHOLD']:
            score += 0.3 * min(flow.total_bytes_out / exfil_config['OUTBOUND_DATA_THRESHOLD'], 2.0)
        
        # Característica 2: Alta tasa de subida
        if hasattr(flow, 'upload_rate') and flow.upload_rate > exfil_config['UPLOAD_RATE_THRESHOLD']:
            score += 0.2 * min(flow.upload_rate / exfil_config['UPLOAD_RATE_THRESHOLD'], 2.0)
        
        # Característica 3: Uso de puertos inusuales
        dst_port = 0
        try:
            dst_port = int(flow.dst_port)
        except (ValueError, TypeError):
            pass
            
        if dst_port in exfil_config['UNUSUAL_PORT_LIST']:
            score += 0.2
        
        # Característica 4: Sesiones largas y continuas
        if flow.flow_duration > 300 and len(flow.packets) > 100:  # > 5 minutos
            score += 0.1
        
        # Característica 5: Consultas DNS anormalmente largas (posible DNS tunneling)
        if hasattr(flow, 'dns_queries') and flow.dns_queries:
            long_queries = sum(1 for q in flow.dns_queries 
                              if len(q) > exfil_config['DNS_QUERY_LENGTH_THRESHOLD'])
            if long_queries > 0:
                score += 0.2 * min(long_queries / 10, 1.0)
        
        # Característica 6: Identificación de datos sensibles en texto plano
        if hasattr(flow, 'http_payloads') and flow.http_payloads:
            sensitive_patterns = [re.compile(pattern) for pattern in exfil_config['UNENCRYPTED_SENSITIVE_PATTERNS']]
            
            for payload in flow.http_payloads:
                if isinstance(payload, bytes):
                    payload_str = payload.decode('utf-8', 'ignore')
                else:
                    payload_str = str(payload)
                
                if any(pattern.search(payload_str) for pattern in sensitive_patterns):
                    score += 0.3
                    break
        
        return min(score, 1.0)
    
    @staticmethod
    def check_malware_traffic(flow, dns_cache) -> float:
        """Verifica patrones de tráfico de malware"""
        score = 0.0
        malware_config = CONFIG['MALWARE_TRAFFIC']
        
        # Característica 1: Comunicación periódica (beaconing)
        if len(flow.inter_arrival_times) > 10:
            iat_std = np.std(flow.inter_arrival_times)
            iat_mean = np.mean(flow.inter_arrival_times)
            if iat_mean > 0 and iat_std / iat_mean < malware_config['PERIODIC_BEACONING_THRESHOLD']:
                score += 0.2
        
        # Característica 2: Dominio sospechoso (alta entropía, potencial DGA)
        domain = None
        try:
            domain = dns_cache.get_domain(flow.dst_ip)
        except:
            pass
            
        if domain and dns_cache.is_domain_suspicious(domain):
            score += 0.3
            
        # Característica 3: Errores en certificados TLS
        if hasattr(flow, 'tls_errors') and flow.tls_errors > malware_config['TLS_INVALID_CERT_THRESHOLD']:
            score += 0.15
        
        # Característica 4: Conexiones a puertos inusuales persistentes
        unusual_ports = {22, 23, 445, 1433, 3389, 5900, 5901, 6667, 8080, 9001, 31337}
        try:
            dst_port = int(flow.dst_port)
            if dst_port in unusual_ports and flow.flow_duration > 300:  # > 5 minutos
                score += 0.15
        except:
            pass
        
        # Característica 5: Entropía alta en payloads pequeños (posible comando cifrado)
        if hasattr(flow, 'payload_entropy') and flow.payload_entropy > 0.8 and hasattr(flow, 'avg_payload_size') and flow.avg_payload_size < 100:
            score += 0.2
        
        # Característica 6: Tráfico cifrado en puertos no estándar para TLS
        standard_tls_ports = {443, 636, 989, 990, 992, 993, 994, 995, 8443}
        if hasattr(flow, 'is_encrypted') and flow.is_encrypted:
            try:
                dst_port = int(flow.dst_port)
                if dst_port not in standard_tls_ports:
                    score += 0.15
            except:
                pass
        
        # Característica 7: JA3 hash conocido como malicioso
        if hasattr(flow, 'ja3_hash') and flow.ja3_hash in malware_config['KNOWN_BAD_JA3_HASHES']:
            score += 0.4
        
        return min(score, 1.0)


class HybridThreatScore:
    """Sistema de puntuación de amenazas que combina ML y patrones de expertos"""
    
    def __init__(self, ml_model, dns_cache):
        self.model = ml_model
        self.dns_cache = dns_cache
        self.pattern_evaluators = {
            'scan': AttackPatterns.check_port_scan,
            'dos': AttackPatterns.check_dos_attack,
            'web': AttackPatterns.check_web_attack,
            'bruteforce': AttackPatterns.check_bruteforce,
            'exfiltration': AttackPatterns.check_data_exfiltration,
            'malware': lambda flow: AttackPatterns.check_malware_traffic(flow, self.dns_cache)
        }
    
    def evaluate_threat(self, flow, features, scaled_features):
        """Evalúa la amenaza de un flujo utilizando ML y patrones"""
        scores = {}
        
        # 1. Obtener puntuación del modelo ML
        model_proba = self.model.predict_proba(scaled_features)[0, 1]
        scores['ml'] = model_proba
        
        # 2. Evaluar patrones específicos para cada tipo de ataque
        pattern_scores = {}
        for attack_type, evaluator in self.pattern_evaluators.items():
            pattern_scores[attack_type] = evaluator(flow)
        
        # 3. Determinar el tipo de ataque principal (mayor puntuación)
        primary_attack_type = max(pattern_scores.items(), key=lambda x: x[1])[0]
        primary_attack_score = pattern_scores[primary_attack_type]
        
        # 4. Verificar reputación
        reputation_score = self._check_reputation(flow)
        scores['reputation'] = reputation_score
        
        # 5. Calcular puntuación combinada
        # Peso mayor al modelo ML (70%), seguido de patrones de expertos (20%) y reputación (10%)
        combined_score = (0.7 * model_proba + 
                         0.2 * primary_attack_score + 
                         0.1 * reputation_score)
        
        # 6. Refinar según tipo de ataque detectado
        # Si un patrón específico tiene alta puntuación, aumentar la influencia
        if primary_attack_score > 0.8:
            # Dar más peso al patrón si es muy claro
            combined_score = 0.5 * model_proba + 0.4 * primary_attack_score + 0.1 * reputation_score
        
        # 7. Preparar resultado
        result = {
            'score': min(combined_score, 1.0),  # Puntuación final normalizada
            'ml_score': model_proba,
            'pattern_scores': pattern_scores,
            'primary_attack_type': primary_attack_type,
            'primary_attack_score': primary_attack_score,
            'reputation_score': reputation_score,
            # Evaluación final según umbrales
            'classification': self._classify_threat(combined_score)
        }
        
        return result
    
    def _check_reputation(self, flow):
        """Evalúa la reputación del flujo (IPs, dominios)"""
        score = 0.0
        
        # Verificar si las IPs están en listas de confianza
        src_trusted = self._is_trusted_ip(flow.src_ip)
        dst_trusted = self._is_trusted_ip(flow.dst_ip)
        
        if src_trusted and dst_trusted:
            return 0.0  # Ambas IPs confiables
        
        # Verificar dominios
        try:
            src_domain = self.dns_cache.get_domain(flow.src_ip)
            dst_domain = self.dns_cache.get_domain(flow.dst_ip)
            
            if self._is_trusted_domain(src_domain) or self._is_trusted_domain(dst_domain):
                return 0.0  # Al menos un dominio es confiable
        except:
            pass
        
        # Verificar si las IPs están en listas negras
        # (En una implementación real, aquí integrarías con servicios externos)
        # Por ahora, simplificamos usando heurísticas basadas en comportamiento previo
        
        # Verificar si la IP destino es conocida como maliciosa
        # (Aquí se integraría con listas negras o servicios de reputación)
        # Por ejemplo: score += check_ip_blacklist(flow.dst_ip)
        
        # Si no hay información específica de reputación, retornamos un valor neutral
        return 0.1  # Valor base pequeño para IPs desconocidas
    
    def _is_trusted_ip(self, ip):
        """Determina si una IP está en rangos confiables"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in CONFIG['REPUTATION']['TRUSTED_NETWORKS']:
                try:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return True
                except:
                    continue
        except:
            pass
        return False
    
    def _is_trusted_domain(self, domain):
        """Determina si un dominio está en la lista de confianza"""
        if not domain:
            return False
            
        return any(trusted in domain for trusted in CONFIG['REPUTATION']['TRUSTED_DOMAINS'])
    
    def _classify_threat(self, score):
        """Clasifica la amenaza según su puntuación final"""
        if score < CONFIG['NORMAL_THRESHOLD']:
            return 'normal'
        elif score < CONFIG['SUSPICIOUS_THRESHOLD']:
            return 'suspicious'
        else:
            return 'attack'


class FlowRecord:
    """Almacena y analiza información de flujos de red"""
    
    __slots__ = [
        # Identificadores y metadatos básicos
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
        'start_time', 'last_update', 'creation_time',
        
        # Almacenamiento de paquetes
        'packets', 'packet_lengths', 'packet_times', 
        'last_packet_time', 'flow_duration',
        
        # Métricas de dirección
        'fwd_packets', 'bwd_packets',
        'fwd_inter_arrival_times', 'bwd_inter_arrival_times',
        'inter_arrival_times',
        
        # Banderas TCP y estado de conexión
        'flags', 'connection_state', 'connection_attempts', 'failed_connections',
        'retransmissions', 'out_of_order',
        
        # Detección de escaneo
        'is_scan_suspect', 'ports_seen',
        
        # Tráfico web y análisis HTTP
        'web_traffic', 'http_methods', 'http_status_codes', 'http_payloads',
        'payload_entropy', 'payload_sizes', 'avg_payload_size',
        
        # Detección de fuerza bruta
        'authentication_attempts', 'authentication_failures', 'packet_similarity',
        
        # Detección de exfiltración
        'total_bytes_out', 'upload_rate', 'dns_queries',
        
        # Detección de malware
        'tls_errors', 'is_encrypted', 'ja3_hash', 'periodic_behavior',
        
        # Metricas de flujo
        'packet_rate', 'byte_rate'
    ]
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Identificación básica
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Tiempos
        self.start_time = None
        self.last_update = time.time()
        self.creation_time = time.time()
        self.last_packet_time = None
        self.flow_duration = 0
        
        # Paquetes
        self.packets = []
        self.packet_lengths = []
        self.packet_times = []
        self.inter_arrival_times = []
        
        # Direccionalidad
        self.fwd_packets = []  # Origen -> Destino
        self.bwd_packets = []  # Destino -> Origen
        self.fwd_inter_arrival_times = []
        self.bwd_inter_arrival_times = []
        
        # Banderas TCP
        self.flags = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 
            'PSH': 0, 'ACK': 0, 'URG': 0
        }
        
        # Estado de conexión
        self.connection_state = "UNKNOWN"
        self.connection_attempts = 0
        self.failed_connections = 0
        self.retransmissions = 0
        self.out_of_order = 0
        
        # Detección de escaneo
        self.is_scan_suspect = False
        self.ports_seen = set()
        
        # Análisis web
        self.web_traffic = False
        self.http_methods = Counter()
        self.http_status_codes = Counter()
        self.http_payloads = []
        self.payload_entropy = 0
        self.payload_sizes = []
        self.avg_payload_size = 0
        
        # Detección de fuerza bruta
        self.authentication_attempts = 0
        self.authentication_failures = 0
        self.packet_similarity = 0
        
        # Exfiltración de datos
        self.total_bytes_out = 0
        self.upload_rate = 0
        self.dns_queries = []
        
        # Detección de malware
        self.tls_errors = 0
        self.is_encrypted = False
        self.ja3_hash = None
        self.periodic_behavior = 0
        
        # Métricas de tasa
        self.packet_rate = 0
        self.byte_rate = 0
    
    def add_packet(self, packet, timestamp):
        """Añade un paquete al flujo y actualiza todas las estadísticas"""
        try:
            # Inicializar tiempo de inicio si es el primer paquete
            if not self.start_time:
                self.start_time = timestamp
            
            # Calcular tiempos entre llegadas
            if self.last_packet_time:
                iat = timestamp - self.last_packet_time
                self.inter_arrival_times.append(iat)
            
            self.last_packet_time = timestamp
            self.flow_duration = timestamp - self.start_time
            self.last_update = time.time()
            
            # Almacenar paquete y tiempo
            self.packet_times.append(timestamp)
            self.packets.append(packet)
            
            # Extraer longitud del paquete con manejo seguro
            packet_len = self._safe_get_packet_length(packet)
            self.packet_lengths.append(packet_len)
            
            # Determinar dirección del paquete
            is_forward = self._is_forward_packet(packet)
            
            # Actualizar contadores direccionales
            if is_forward:
                self.fwd_packets.append(packet_len)
                self.total_bytes_out += packet_len
                if len(self.fwd_packets) > 1 and self.inter_arrival_times:
                    self.fwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            else:
                self.bwd_packets.append(packet_len)
                if len(self.bwd_packets) > 1 and self.inter_arrival_times:
                    self.bwd_inter_arrival_times.append(self.inter_arrival_times[-1])
            
            # Actualizar tasas
            if self.flow_duration > 0:
                self.packet_rate = len(self.packets) / self.flow_duration
                self.byte_rate = sum(self.packet_lengths) / self.flow_duration
                self.upload_rate = sum(self.fwd_packets) / self.flow_duration
            
            # Procesar protocolos específicos
            if hasattr(packet, 'tcp'):
                self._process_tcp_packet(packet)
            elif hasattr(packet, 'udp'):
                self._process_udp_packet(packet)
            elif hasattr(packet, 'icmp'):
                self._process_icmp_packet(packet)
            
            # Analizar patrones de periodicidad
            self._analyze_periodicity()
            
            # Verificar similitud entre paquetes (útil para bruteforce)
            self._update_packet_similarity()
            
            # Actualizar estadísticas de payload
            if self.payload_sizes:
                self.avg_payload_size = sum(self.payload_sizes) / len(self.payload_sizes)
        
        except Exception as e:
            # Ignorar errores en procesamiento de paquetes para mayor robustez
            pass
    
    def _safe_get_packet_length(self, packet):
        """Extrae de forma segura la longitud de un paquete"""
        try:
            if hasattr(packet, 'length'):
                length_value = getattr(packet, 'length')
                if isinstance(length_value, (int, float)):
                    return int(length_value)
                if isinstance(length_value, str) and length_value.isdigit():
                    return int(length_value)
            # Alternativas si no tiene atributo length
            if hasattr(packet, 'ip') and hasattr(packet.ip, 'len'):
                try:
                    return int(packet.ip.len)
                except (ValueError, TypeError):
                    pass
        except:
            pass
        
        # Valor predeterminado basado en paquetes anteriores o un valor fijo
        return len(self.packet_lengths) > 0 and int(np.mean(self.packet_lengths)) or 64
    
    def _is_forward_packet(self, packet):
        """Determina si un paquete va en dirección forward (src->dst)"""
        if hasattr(packet, 'ip'):
            return packet.ip.src == self.src_ip and packet.ip.dst == self.dst_ip
        return True  # Valor predeterminado si no se puede determinar
    
    def _process_tcp_packet(self, packet):
        """Procesa un paquete TCP para extraer información relevante"""
        # Procesar banderas TCP
        for flag in self.flags:
            flag_name = flag.lower()
            if hasattr(packet.tcp, flag_name):
                try:
                    flag_value = getattr(packet.tcp, flag_name)
                    # Manejar diferentes formatos (0/1, True/False, etc)
                    if isinstance(flag_value, bool) and flag_value:
                        self.flags[flag] += 1
                    elif isinstance(flag_value, (int, float)) and flag_value > 0:
                        self.flags[flag] += 1
                    elif isinstance(flag_value, str):
                        if flag_value.isdigit() and int(flag_value) > 0:
                            self.flags[flag] += 1
                        elif flag_value.lower() in ('true', 'yes', '1'):
                            self.flags[flag] += 1
                except:
                    pass
        
        # Analizar estado de conexión
        self._update_connection_state()
        
        # Detectar retransmisiones y paquetes fuera de orden
        if hasattr(packet.tcp, 'analysis_retransmission'):
            self.retransmissions += 1
        if hasattr(packet.tcp, 'analysis_out_of_order'):
            self.out_of_order += 1
        
        # Extraer puerto destino para análisis de escaneo
        try:
            if hasattr(packet.tcp, 'dstport'):
                dst_port_val = getattr(packet.tcp, 'dstport')
                if isinstance(dst_port_val, int):
                    self.ports_seen.add(dst_port_val)
                elif isinstance(dst_port_val, str) and dst_port_val.isdigit():
                    self.ports_seen.add(int(dst_port_val))
        except:
            pass
        
        # Detectar tráfico web
        self._detect_web_traffic(packet)
        
        # Detectar TLS/cifrado
        self._detect_encryption(packet)
        
        # Extraer y analizar payload
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            try:
                payload = packet.tcp.payload
                if payload:
                    # Calcular tamaño
                    payload_size = len(payload) if isinstance(payload, bytes) else len(str(payload))
                    self.payload_sizes.append(payload_size)
                    
                    # Calcular entropía
                    self.payload_entropy = max(self.payload_entropy, self._calculate_entropy(payload))
            except:
                pass
    
    def _process_udp_packet(self, packet):
        """Procesa un paquete UDP para extraer información"""
        # Detectar tráfico DNS
        if hasattr(packet, 'dns'):
            self._process_dns_packet(packet)
        
        # Verificar puertos web
        try:
            if hasattr(packet.udp, 'dstport'):
                dst_port = self._safe_parse_int(packet.udp.dstport)
                if dst_port in CONFIG['WEB_PORTS']:
                    self.web_traffic = True
        except:
            pass
        
        # Extraer y analizar payload
        if hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
            try:
                payload = packet.udp.payload
                if payload:
                    # Calcular tamaño
                    payload_size = len(payload) if isinstance(payload, bytes) else len(str(payload))
                    self.payload_sizes.append(payload_size)
                    
                    # Calcular entropía
                    self.payload_entropy = max(self.payload_entropy, self._calculate_entropy(payload))
            except:
                pass
    
    def _process_dns_packet(self, packet):
        """Procesa un paquete DNS"""
        try:
            if hasattr(packet.dns, 'qry_name'):
                query = packet.dns.qry_name
                self.dns_queries.append(query)
        except:
            pass
    
    def _process_icmp_packet(self, packet):
        """Procesa un paquete ICMP"""
        # Solo registrar para estadísticas
        pass
    
    def _update_connection_state(self):
        """Actualiza el estado de la conexión TCP basado en banderas"""
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
    
    def _detect_web_traffic(self, packet):
        """Detecta y analiza tráfico web"""
        # Verificar puertos web
        try:
            src_port = self._safe_parse_int(getattr(packet.tcp, 'srcport', 0))
            dst_port = self._safe_parse_int(getattr(packet.tcp, 'dstport', 0))
            
            if src_port in CONFIG['WEB_PORTS'] or dst_port in CONFIG['WEB_PORTS']:
                self.web_traffic = True
                
                # Procesar HTTP si está presente
                if hasattr(packet, 'http'):
                    self._process_http_packet(packet)
        except:
            pass
    
    def _safe_parse_int(self, value):
        """Convierte un valor a entero de forma segura"""
        if isinstance(value, int):
            return value
        elif isinstance(value, str) and value.isdigit():
            return int(value)
        return 0
    
    def _process_http_packet(self, packet):
        """Procesa un paquete HTTP"""
        try:
            if hasattr(packet.http, 'request_method'):
                self.http_methods[packet.http.request_method] += 1
            
            if hasattr(packet.http, 'response_code'):
                self.http_status_codes[packet.http.response_code] += 1
            
            # Analizar payload
            if hasattr(packet.http, 'file_data'):
                self.http_payloads.append(packet.http.file_data)
                self.payload_entropy = max(self.payload_entropy, 
                                          self._calculate_entropy(packet.http.file_data))
            
            # Detectar intentos de autenticación (formularios, login)
            if (hasattr(packet.http, 'request_uri') and 
                any(term in str(packet.http.request_uri).lower() 
                    for term in ['login', 'auth', 'signin', 'session'])):
                self.authentication_attempts += 1
                
                # Verificar si hay indicios de fallo
                if hasattr(packet.http, 'response_code') and packet.http.response_code in ('401', '403'):
                    self.authentication_failures += 1
        except:
            pass
    
    def _detect_encryption(self, packet):
        """Detecta tráfico cifrado"""
        # Verificar TLS
        if hasattr(packet, 'tls'):
            self.is_encrypted = True
            
            # Detección de errores TLS
            if hasattr(packet.tls, 'handshake_failure') or hasattr(packet.tls, 'alert_message'):
                self.tls_errors += 1
            
            # Extraer JA3 fingerprint si está disponible
            if hasattr(packet.tls, 'handshake_ja3'):
                self.ja3_hash = packet.tls.handshake_ja3
        
        # Heurística simple para detectar tráfico cifrado no-TLS 
        # (alta entropía pero no protocolo reconocido)
        elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            try:
                payload = packet.tcp.payload
                if payload and len(payload) > 20:
                    entropy = self._calculate_entropy(payload)
                    # Entropía muy alta típica de datos cifrados
                    if entropy > 0.9:
                        self.is_encrypted = True
            except:
                pass
    
    def _analyze_periodicity(self):
        """Analiza periodicidad en las comunicaciones"""
        # Para detectar beacons y comunicación automatizada
        if len(self.inter_arrival_times) > 5:
            # Calcular variación en los últimos 5 intervalos
            recent_iats = self.inter_arrival_times[-5:]
            iat_std = np.std(recent_iats)
            iat_mean = np.mean(recent_iats)
            
            # Baja variación indica comportamiento periódico
            if iat_mean > 0 and iat_std / iat_mean < 0.1:
                self.periodic_behavior += 1
    
    def _update_packet_similarity(self):
        """Actualiza la medida de similitud entre paquetes consecutivos"""
        # Útil para detectar ataques de fuerza bruta donde solo cambian pequeños bits
        if len(self.packets) < 3:
            return
            
        try:
            # Calculamos similitud solo entre últimos paquetes
            last_payloads = []
            for i in range(min(3, len(self.packets))):
                idx = -(i+1)  # Últimos 3 paquetes
                packet = self.packets[idx]
                
                if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                    last_payloads.append(str(packet.tcp.payload))
                elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                    last_payloads.append(str(packet.udp.payload))
            
            # Si tenemos al menos 2 payloads, calcular similitud
            if len(last_payloads) >= 2:
                # Método simple: calcular longitud del prefijo común más largo
                p1, p2 = last_payloads[0], last_payloads[1]
                common_prefix = 0
                for i in range(min(len(p1), len(p2))):
                    if p1[i] == p2[i]:
                        common_prefix += 1
                    else:
                        break
                
                # Normalizar por longitud
                max_len = max(len(p1), len(p2))
                if max_len > 0:
                    self.packet_similarity = common_prefix / max_len
        except:
            pass
    
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
        """Extrae características del flujo para el modelo de ML"""
        
        # Evitar divisiones por cero
        n_packets = max(1, len(self.packets))
        fwd_packets = max(1, len(self.fwd_packets))
        bwd_packets = max(1, len(self.bwd_packets))
        flow_duration = max(0.001, self.flow_duration)
        
        # Características básicas de flujo
        total_fwd_packets = len(self.fwd_packets)
        total_bwd_packets = len(self.bwd_packets)
        
        # Longitudes de paquetes
        total_fwd_length = sum(self.fwd_packets) if self.fwd_packets else 0
        total_bwd_length = sum(self.bwd_packets) if self.bwd_packets else 0
        
        # Estadísticas de tamaño de paquetes
        has_packets = len(self.packet_lengths) > 0
        packet_length_mean = np.mean(self.packet_lengths) if has_packets else 0
        packet_length_std = np.std(self.packet_lengths) if has_packets and len(self.packet_lengths) > 1 else 0
        packet_length_variance = np.var(self.packet_lengths) if has_packets and len(self.packet_lengths) > 1 else 0
        min_packet_length = min(self.packet_lengths) if has_packets else 0
        max_packet_length = max(self.packet_lengths) if has_packets else 0
        
        # Promedios de segmentos
        avg_fwd_segment_size = np.mean(self.fwd_packets) if self.fwd_packets else 0
        avg_bwd_segment_size = np.mean(self.bwd_packets) if self.bwd_packets else 0
        
        # Tasas de flujo
        flow_bytes_per_sec = (total_fwd_length + total_bwd_length) / flow_duration
        flow_packets_per_sec = n_packets / flow_duration
        
        # Tiempos entre llegadas
        has_iats = len(self.inter_arrival_times) > 0
        flow_iat_mean = np.mean(self.inter_arrival_times) if has_iats else 0
        flow_iat_std = np.std(self.inter_arrival_times) if has_iats and len(self.inter_arrival_times) > 1 else 0
        flow_iat_max = max(self.inter_arrival_times) if has_iats else 0
        flow_iat_min = min(self.inter_arrival_times) if has_iats else 0
        
        has_fwd_iats = len(self.fwd_inter_arrival_times) > 0
        fwd_iat_mean = np.mean(self.fwd_inter_arrival_times) if has_fwd_iats else 0
        fwd_iat_std = np.std(self.fwd_inter_arrival_times) if has_fwd_iats and len(self.fwd_inter_arrival_times) > 1 else 0
        fwd_iat_max = max(self.fwd_inter_arrival_times) if has_fwd_iats else 0
        fwd_iat_min = min(self.fwd_inter_arrival_times) if has_fwd_iats else 0
        
        has_bwd_iats = len(self.bwd_inter_arrival_times) > 0
        bwd_iat_mean = np.mean(self.bwd_inter_arrival_times) if has_bwd_iats else 0
        bwd_iat_std = np.std(self.bwd_inter_arrival_times) if has_bwd_iats and len(self.bwd_inter_arrival_times) > 1 else 0
        bwd_iat_max = max(self.bwd_inter_arrival_times) if has_bwd_iats else 0
        bwd_iat_min = min(self.bwd_inter_arrival_times) if has_bwd_iats else 0
        
        # Crear diccionario de características
        features = {
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_backward_packets': total_bwd_packets,
            'total_length_of_fwd_packets': total_fwd_length,
            'total_length_of_bwd_packets': total_bwd_length,
            'flow_bytes/s': flow_bytes_per_sec,
            'flow_packets/s': flow_packets_per_sec,
            
            # IAT (Inter Arrival Time) - tiempos entre paquetes
            'flow_iat_mean': flow_iat_mean,
            'flow_iat_std': flow_iat_std,
            'flow_iat_max': flow_iat_max,
            'flow_iat_min': flow_iat_min,
            'fwd_iat_mean': fwd_iat_mean,
            'fwd_iat_std': fwd_iat_std,
            'fwd_iat_max': fwd_iat_max,
            'fwd_iat_min': fwd_iat_min,
            'bwd_iat_mean': bwd_iat_mean,
            'bwd_iat_std': bwd_iat_std,
            'bwd_iat_max': bwd_iat_max,
            'bwd_iat_min': bwd_iat_min,
            
            # Flags TCP
            'fin_flag_count': self.flags['FIN'],
            'syn_flag_count': self.flags['SYN'],
            'rst_flag_count': self.flags['RST'],
            'psh_flag_count': self.flags['PSH'],
            'ack_flag_count': self.flags['ACK'],
            'urg_flag_count': self.flags['URG'],
            
            # Estadísticas de tamaño de paquetes
            'packet_length_mean': packet_length_mean,
            'packet_length_std': packet_length_std,
            'packet_length_variance': packet_length_variance,
            'min_packet_length': min_packet_length,
            'max_packet_length': max_packet_length,
            'avg_fwd_segment_size': avg_fwd_segment_size,
            'avg_bwd_segment_size': avg_bwd_segment_size,
            
            # Subflujos (para compatibilidad con CICIDS2017)
            'subflow_fwd_packets': total_fwd_packets,
            'subflow_fwd_bytes': total_fwd_length,
            'subflow_bwd_packets': total_bwd_packets,
            'subflow_bwd_bytes': total_bwd_length,
            
            # Características adicionales
            'fwd_header_length': total_fwd_packets * 20,  # Aproximación de encabezado TCP/IP
            'bwd_header_length': total_bwd_packets * 20,  # Aproximación de encabezado TCP/IP
            'fwd_packets/s': total_fwd_packets / flow_duration,
            'bwd_packets/s': total_bwd_packets / flow_duration,
            
            # Características de estado TCP
            'connection_state': 1 if self.connection_state == "ESTABLISHED" else 0,
            'retransmissions': self.retransmissions,
            'out_of_order': self.out_of_order,
            
            # Características especiales para detección específica
            'port_scan_suspect': 1 if len(self.ports_seen) >= CONFIG['PORT_SCAN']['MIN_PORTS'] else 0,
            'periodic_behavior': self.periodic_behavior,
            'is_encrypted': 1 if self.is_encrypted else 0,
            'payload_entropy': self.payload_entropy
        }
        
        return features


class NetworkMonitor:
    """Monitor de red para detección de intrusiones en tiempo real"""
    
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
        
        # Hilos de trabajo
        self.capture_thread = None
        self.cleanup_thread = None
        self.stats_thread = None
        self.thread_pool = ThreadPoolExecutor(max_workers=CONFIG['MAX_THREADS'])
        
        # Modo aprendizaje
        self.learning_mode = CONFIG['LEARNING_MODE']
        self.learning_end_time = time.time() + CONFIG['LEARNING_DURATION'] if self.learning_mode else 0
        
        # Carga del modelo
        try:
            logger.info(f"Cargando modelo desde {model_path}")
            model_data = joblib.load(model_path)
            
            if isinstance(model_data, dict):
                # Modelo con metadatos
                self.model = model_data['model']
                self.scaler = model_data.get('scaler')
                self.selected_features = model_data.get('selected_features', [])
            else:
                # Modelo directo
                self.model = model_data
                self.scaler = None
                self.selected_features = []
                
            logger.info("Modelo cargado exitosamente")
        except Exception as e:
            logger.error(f"Error cargando el modelo: {e}")
            raise
        
        # Sistema de DNS caché
        self.dns_cache = DNSCache(max_size=CONFIG['REPUTATION']['DOMAIN_CACHE_SIZE'])
        
        # Evaluador de amenazas híbrido
        self.threat_evaluator = HybridThreatScore(self.model, self.dns_cache)
        
        # Contadores estadísticos
        self.alert_counts = {
            'normal': 0,
            'suspicious': 0,
            'attack': 0
        }
        
        # Contador por tipo de ataque
        self.attack_types = {
            'scan': 0,
            'dos': 0,
            'web': 0,
            'bruteforce': 0,
            'exfiltration': 0,
            'malware': 0,
            'other': 0
        }
        
        # Cola para registro de detecciones recientes
        self.recent_detections = deque(maxlen=500)
        
        # Parámetros de rendimiento
        self.performance_metrics = {
            'start_time': time.time(),
            'packets_processed': 0,
            'flows_analyzed': 0,
            'processing_times': deque(maxlen=1000),
            'detection_times': deque(maxlen=100)
        }
        
        # Historial para aprendizaje
        self.detection_history = []
        
        # Lista blanca de IPs y flujos conocidos
        self.whitelisted_ips = set()
        self.trusted_flows = set()
        self.load_whitelist()
    
    def load_whitelist(self):
        """Carga lista blanca desde archivo"""
        try:
            whitelist_file = "whitelist.json"
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    data = json.load(f)
                    
                    # Cargar IPs en lista blanca
                    if 'ips' in data:
                        self.whitelisted_ips.update(data['ips'])
                    
                    # Cargar flujos confiables
                    if 'flows' in data:
                        self.trusted_flows.update(data['flows'])
                        
                    logger.info(f"Lista blanca cargada: {len(self.whitelisted_ips)} IPs y {len(self.trusted_flows)} flujos")
        except Exception as e:
            logger.error(f"Error cargando lista blanca: {e}")
    
    def save_whitelist(self):
        """Guarda lista blanca a archivo"""
        try:
            whitelist_file = "whitelist.json"
            data = {
                'ips': list(self.whitelisted_ips),
                'flows': list(self.trusted_flows)
            }
            
            with open(whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.info(f"Lista blanca guardada: {len(self.whitelisted_ips)} IPs y {len(self.trusted_flows)} flujos")
        except Exception as e:
            logger.error(f"Error guardando lista blanca: {e}")
    
    def add_to_whitelist(self, ip=None, flow_id=None):
        """Añade una IP o flujo a la lista blanca"""
        if ip:
            self.whitelisted_ips.add(ip)
            logger.info(f"IP {ip} añadida a lista blanca")
        
        if flow_id:
            self.trusted_flows.add(flow_id)
            logger.info(f"Flujo {flow_id} añadido a lista blanca")
        
        # Guardar cambios
        self.save_whitelist()
    
    def is_whitelisted(self, ip=None, flow_id=None):
        """Verifica si una IP o flujo está en lista blanca"""
        if ip and ip in self.whitelisted_ips:
            return True
        
        if flow_id and flow_id in self.trusted_flows:
            return True
        
        return False
    
    def start_capture(self):
        """Inicia la captura de paquetes y monitoreo en hilos separados"""
        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("La captura ya está en ejecución")
            return
        
        self.stop_capture.clear()
        
        # Crear hilos de trabajo
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.cleanup_thread = threading.Thread(target=self._cleanup_flows)
        self.stats_thread = threading.Thread(target=self._print_stats)
        
        # Configurar como daemons (terminarán cuando el programa principal termine)
        self.capture_thread.daemon = True
        self.cleanup_thread.daemon = True
        self.stats_thread.daemon = True
        
        # Registrar handler para SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Mostrar mensaje inicial
        logger.info(f"Iniciando captura en interfaz {self.interface}")
        print(f"{CONFIG['COLORS']['BOLD']}Sistema Avanzado de Detección de Intrusiones iniciado en {self.interface}{CONFIG['COLORS']['RESET']}")
        
        if self.learning_mode:
            print(f"{CONFIG['COLORS']['YELLOW']}Modo Aprendizaje activado por {CONFIG['LEARNING_DURATION']} segundos{CONFIG['COLORS']['RESET']}")
        
        print(f"Umbrales - Normal: {CONFIG['NORMAL_THRESHOLD']}, Sospechoso: {CONFIG['SUSPICIOUS_THRESHOLD']}")
        print(f"Presione Ctrl+C para detener la captura\n")
        
        # Iniciar hilos
        self.capture_thread.start()
        self.cleanup_thread.start()
        self.stats_thread.start()
    
    def stop_capture_threads(self):
        """Detiene todos los hilos de captura de forma limpia"""
        logger.info("Deteniendo hilos de captura")
        self.stop_capture.set()
        
        # Esperar a que terminen los hilos (con timeout)
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)
        if self.stats_thread:
            self.stats_thread.join(timeout=2.0)
        
        # Cerrar el pool de threads
        self.thread_pool.shutdown(wait=False)
    
    def _signal_handler(self, sig, frame):
        """Maneja la señal de interrupción (CTRL+C)"""
        print("\nDeteniendo captura... Por favor espere.")
        self.stop_capture_threads()
        print("\nEstadísticas finales:")
        self._print_final_stats()
        sys.exit(0)
    
    def _capture_packets(self):
        """Función principal para capturar y procesar paquetes"""
        try:
            # Configurar event loop para pyshark
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            except Exception:
                # Si no se puede crear el event loop, continuar sin él
                pass
            
            # Iniciar captura con un filtro óptimo
            try:
                capture = pyshark.LiveCapture(interface=self.interface, bpf_filter='ip')
                logger.info(f"Captura iniciada en {self.interface} con filtro 'ip'")
            except Exception:
                # Si falla con filtro, intentar sin filtro
                capture = pyshark.LiveCapture(interface=self.interface)
                logger.info(f"Captura iniciada en {self.interface} sin filtro")
            
            # Capturar paquetes continuamente
            for packet in capture.sniff_continuously():
                if self.stop_capture.is_set():
                    break
                
                try:
                    # Procesar en un thread separado del pool
                    self.thread_pool.submit(self._process_packet, packet)
                    self.performance_metrics['packets_processed'] += 1
                except Exception as e:
                    logger.error(f"Error procesando paquete: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error en captura: {str(e)}")
            print(f"{CONFIG['COLORS']['RED']}Error en captura: {str(e)}{CONFIG['COLORS']['RESET']}")
            traceback.print_exc()
    
    def _process_packet(self, packet):
        """Procesa un paquete y lo añade al flujo correspondiente"""
        try:
            start_time = time.time()
            
            # Verificar si es un paquete IP
            if not hasattr(packet, 'ip'):
                return
            
            # Obtener información básica
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Si ambas IPs están en lista blanca, ignorar el paquete
            if self.is_whitelisted(ip=src_ip) and self.is_whitelisted(ip=dst_ip):
                return
            
            # Valores por defecto para puertos y protocolo
            src_port = dst_port = '0'
            protocol = packet.ip.proto
            
            # Obtener información específica por protocolo
            try:
                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    protocol = 'TCP'
                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                    protocol = 'UDP'
                elif hasattr(packet, 'icmp'):
                    protocol = 'ICMP'
            except Exception:
                # Si hay error al obtener puertos, usar valores predeterminados
                pass
            
            # Crear identificador único para el flujo
            # Normalizar dirección (menor IP/puerto primero para consistencia)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            # Si el flujo está en lista blanca, ignorarlo
            if self.is_whitelisted(flow_id=flow_id):
                return
            
            # Añadir paquete al flujo correspondiente
            with self.flow_lock:
                # Verificar límite de flujos
                if len(self.flows) >= CONFIG['MAX_FLOWS']:
                    self._prune_old_flows()
                
                # Crear nuevo flujo si no existe
                if flow_id not in self.flows:
                    self.flows[flow_id] = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
                
                # Obtener timestamp del paquete
                try:
                    timestamp = float(packet.sniff_timestamp)
                except (ValueError, AttributeError):
                    timestamp = time.time()  # Si no hay timestamp, usar tiempo actual
                
                # Añadir paquete al flujo
                self.flows[flow_id].add_packet(packet, timestamp)
                
                # Verificar si tenemos suficientes paquetes para analizar el flujo
                min_packets = 5  # Mínimo de paquetes para analizar
                if len(self.flows[flow_id].packets) >= min_packets:
                    # En modo aprendizaje, solo evaluamos
                    if self.learning_mode and time.time() < self.learning_end_time:
                        # Evaluar sin alertar para crear línea base
                        self._evaluate_flow_baseline(flow_id)
                    else:
                        # Evaluación completa con alertas
                        self._evaluate_flow(flow_id)
            
            # Registrar tiempo de procesamiento
            proc_time = time.time() - start_time
            self.performance_metrics['processing_times'].append(proc_time)
            
        except Exception as e:
            logger.error(f"Error procesando paquete: {str(e)}")
    
    def _evaluate_flow_baseline(self, flow_id):
        """Evalúa un flujo en modo aprendizaje para crear línea base"""
        try:
            flow = self.flows[flow_id]
            
            # Extraer características para el modelo
            features = flow.get_features()
            
            # Verificar si tenemos todas las características necesarias
            if not self.selected_features:
                # Si no tenemos lista predefinida, usar todas las características
                X = [features[f] for f in sorted(features.keys())]
                X = np.array([X])
                
                if self.scaler:
                    X_scaled = self.scaler.transform(X)
                else:
                    X_scaled = X
            else:
                # Verificar que estén todas las características requeridas
                missing_features = [f for f in self.selected_features if f not in features]
                if missing_features:
                    logger.debug(f"Características faltantes en modo aprendizaje: {missing_features}")
                    return
                    
                # Extraer solo las características necesarias
                X = [features[f] for f in self.selected_features]
                X = np.array([X])
                
                # Aplicar escalado si existe
                if self.scaler:
                    X_scaled = self.scaler.transform(X)
                else:
                    X_scaled = X
            
            # Obtener predicción y guardar para aprendizaje
            # (no alertamos en modo aprendizaje)
            y_proba = self.model.predict_proba(X_scaled)[0, 1]
            
            # Guardar para aprendizaje
            self.detection_history.append({
                'flow_id': flow_id,
                'features': features,
                'prediction': y_proba,
                'timestamp': time.time()
            })
            
        except Exception as e:
            logger.error(f"Error evaluando flujo en modo aprendizaje: {str(e)}")
    
    def _evaluate_flow(self, flow_id):
        """Evalúa un flujo para detectar posibles intrusiones"""
        try:
            start_time = time.time()
            flow = self.flows[flow_id]
            
            # Extraer características para el modelo
            features = flow.get_features()
            
            # Verificar si tenemos todas las características necesarias
            if not self.selected_features:
                # Si no tenemos lista predefinida, usar todas las características
                feature_keys = sorted(features.keys())
                X = [features[f] for f in feature_keys]
                X = np.array([X])
                
                if self.scaler:
                    X_scaled = self.scaler.transform(X)
                else:
                    X_scaled = X
            else:
                # Verificar que estén todas las características requeridas
                missing_features = [f for f in self.selected_features if f not in features]
                if missing_features:
                    logger.debug(f"Características faltantes: {missing_features}")
                    return
                    
                # Extraer solo las características necesarias
                X = [features[f] for f in self.selected_features]
                X = np.array([X])
                
                # Aplicar escalado si existe
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
            
            # Si es un ataque, actualizar contador por tipo
            if status == 'attack':
                attack_type = primary_attack_type
                if not (attack_type in self.attack_types):
                    attack_type = 'other'
                self.attack_types[attack_type] += 1
            else:
                attack_type = None
            
            # Determinar nivel de log
            if status == 'normal':
                level = 'info'
            elif status == 'suspicious':
                level = 'warning'
            else:
                level = 'error'
            
            # Crear mensaje detallado
            msg = f"[{status.upper()}] {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} ({flow.protocol}) - Prob: {final_score:.4f}"
            
            if status == 'attack':
                msg += f" - Tipo: {attack_type.upper()}"
                
                if attack_type == 'scan':
                    msg += f" - Puertos: {len(flow.ports_seen)}"
                elif attack_type == 'web':
                    msg += f" - Métodos: {dict(flow.http_methods)}"
                elif attack_type == 'dos':
                    packet_rate = len(flow.packets) / max(0.1, flow.flow_duration)
                    msg += f" - Rate: {packet_rate:.1f} pkt/s"
            
            # Registrar en log según nivel
            getattr(logger, level)(msg)
            
            # Imprimir en consola si corresponde
            if status != 'normal' or CONFIG['SHOW_NORMAL_TRAFFIC']:
                self._print_detection(status, flow, final_score, attack_type, pattern_scores)
            
            # Guardar detección para visualización y referencia
            detection_record = {
                'timestamp': datetime.datetime.now(),
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
            
            self.recent_detections.append(detection_record)
            
            # Si es un ataque de alta confianza, eliminar flujo
            if status == 'attack' and final_score > 0.9:
                del self.flows[flow_id]
            
            # Registrar tiempo de detección
            detection_time = time.time() - start_time
            self.performance_metrics['detection_times'].append(detection_time)
            
        except Exception as e:
            logger.error(f"Error evaluando flujo {flow_id}: {str(e)}")
            traceback.print_exc()
    
    def _cleanup_flows(self):
        """Limpia flujos inactivos periódicamente"""
        while not self.stop_capture.is_set():
            time.sleep(CONFIG['CLEANUP_INTERVAL'])
            
            try:
                current_time = time.time()
                expired_flows = []
                
                with self.flow_lock:
                    # Identificar flujos expirados
                    for flow_id, flow in self.flows.items():
                        if current_time - flow.last_update > self.timeout:
                            expired_flows.append(flow_id)
                            
                            # Evaluar el flujo antes de eliminarlo si tiene suficientes paquetes
                            if len(flow.packets) >= 5:
                                if self.learning_mode and time.time() < self.learning_end_time:
                                    self._evaluate_flow_baseline(flow_id)
                                else:
                                    self._evaluate_flow(flow_id)
                    
                    # Eliminar flujos expirados
                    for flow_id in expired_flows:
                        del self.flows[flow_id]
                
                if expired_flows:
                    logger.debug(f"Eliminados {len(expired_flows)} flujos inactivos")
            
            except Exception as e:
                logger.error(f"Error en limpieza de flujos: {str(e)}")
    
    def _prune_old_flows(self):
        """Elimina los flujos más antiguos cuando se alcanza el límite"""
        try:
            # Ordenar flujos por tiempo de actualización
            flows_by_time = sorted(
                self.flows.items(),
                key=lambda x: x[1].last_update
            )
            
            # Eliminar el 10% más antiguo
            flows_to_remove = flows_by_time[:int(CONFIG['MAX_FLOWS'] * 0.1)]
            for flow_id, _ in flows_to_remove:
                del self.flows[flow_id]
                
            logger.debug(f"Eliminados {len(flows_to_remove)} flujos antiguos para liberar memoria")
        
        except Exception as e:
            logger.error(f"Error eliminando flujos antiguos: {str(e)}")
    
    def _print_detection(self, status, flow, probability, attack_type=None, pattern_scores=None):
        """Imprime una detección formateada en la consola"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if status == 'normal':
            color = CONFIG['COLORS']['GREEN']
            prefix = "[NORMAL]"
        elif status == 'suspicious':
            color = CONFIG['COLORS']['YELLOW']
            prefix = "[SOSPECHOSO]"
        else:
            color = CONFIG['COLORS']['RED']
            prefix = f"[ATAQUE-{attack_type.upper() if attack_type else 'DESCONOCIDO'}]"
        
        message = (f"{color}{timestamp} {prefix} "
                  f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                  f"({flow.protocol}) - Prob: {probability:.4f}{CONFIG['COLORS']['RESET']}")
        
        # Añadir detalles según tipo de ataque
        if status == 'attack' and attack_type:
            if attack_type == 'scan':
                message += f" - Puertos escaneados: {len(flow.ports_seen)}"
            elif attack_type == 'web':
                message += f" - Métodos: {dict(flow.http_methods)}"
            elif attack_type == 'dos':
                packet_rate = len(flow.packets) / max(0.1, flow.flow_duration)
                message += f" - {packet_rate:.1f} pkt/s"
            
            # Añadir score específico si existe
            if pattern_scores and attack_type in pattern_scores:
                message += f" - Score específico: {pattern_scores[attack_type]:.2f}"
        
        print(message)
    
    def _print_stats(self):
        """Imprime estadísticas periódicamente en la consola"""
        last_packet_count = 0
        last_flow_count = 0
        last_time = time.time()
        
        while not self.stop_capture.is_set():
            try:
                # Calcular métricas de rendimiento
                current_time = time.time()
                time_diff = current_time - last_time
                
                # Calcular tasas instantáneas
                packets_diff = self.performance_metrics['packets_processed'] - last_packet_count
                flows_diff = self.performance_metrics['flows_analyzed'] - last_flow_count
                
                packet_rate = packets_diff / time_diff if time_diff > 0 else 0
                flow_rate = flows_diff / time_diff if time_diff > 0 else 0
                
                # Actualizar valores para la próxima comparación
                last_packet_count = self.performance_metrics['packets_processed']
                last_flow_count = self.performance_metrics['flows_analyzed']
                last_time = current_time
                
                # Limpiar pantalla y posicionar cursor
                print("\033[2J\033[H", end='')
                
                # Cabecera
                print(f"{CONFIG['COLORS']['BOLD']}Sistema Avanzado de Detección de Intrusiones - Estadísticas{CONFIG['COLORS']['RESET']}")
                print(f"Interfaz: {self.interface}")
                print(f"Tiempo en ejecución: {self._format_duration(current_time - self.performance_metrics['start_time'])}")
                
                # Mostrar modo aprendizaje si está activo
                if self.learning_mode and current_time < self.learning_end_time:
                    remaining = int(self.learning_end_time - current_time)
                    print(f"{CONFIG['COLORS']['YELLOW']}MODO APRENDIZAJE - Finalizando en {remaining} segundos{CONFIG['COLORS']['RESET']}")
                
                print(f"Umbrales - Normal: {CONFIG['NORMAL_THRESHOLD']}, Sospechoso: {CONFIG['SUSPICIOUS_THRESHOLD']}")
                print("-" * 80)
                
                # Estadísticas básicas
                with self.flow_lock:
                    active_flows = len(self.flows)
                
                print(f"Flujos activos: {active_flows}")
                print(f"Paquetes procesados: {self.performance_metrics['packets_processed']} ({packet_rate:.1f} pkt/s)")
                print(f"Flujos analizados: {self.performance_metrics['flows_analyzed']} ({flow_rate:.1f} flows/s)")
                
                # Tiempos de procesamiento
                if self.performance_metrics['processing_times']:
                    avg_proc_time = sum(self.performance_metrics['processing_times']) / len(self.performance_metrics['processing_times']) * 1000
                    print(f"Tiempo promedio de procesamiento: {avg_proc_time:.2f} ms/pkt")
                
                if self.performance_metrics['detection_times']:
                    avg_detect_time = sum(self.performance_metrics['detection_times']) / len(self.performance_metrics['detection_times']) * 1000
                    print(f"Tiempo promedio de detección: {avg_detect_time:.2f} ms/flujo")
                
                # Estadísticas de alertas
                total_alerts = sum(self.alert_counts.values())
                if total_alerts > 0:
                    normal_pct = (self.alert_counts['normal'] / total_alerts) * 100
                    suspicious_pct = (self.alert_counts['suspicious'] / total_alerts) * 100
                    attack_pct = (self.alert_counts['attack'] / total_alerts) * 100
                    
                    print("\nDistribución de alertas:")
                    print(f"{CONFIG['COLORS']['GREEN']}Normal: {self.alert_counts['normal']} ({normal_pct:.1f}%){CONFIG['COLORS']['RESET']}")
                    print(f"{CONFIG['COLORS']['YELLOW']}Sospechoso: {self.alert_counts['suspicious']} ({suspicious_pct:.1f}%){CONFIG['COLORS']['RESET']}")
                    print(f"{CONFIG['COLORS']['RED']}Ataque: {self.alert_counts['attack']} ({attack_pct:.1f}%){CONFIG['COLORS']['RESET']}")
                
                # Estadísticas de ataques por tipo
                if self.alert_counts['attack'] > 0:
                    print("\nTipos de ataques detectados:")
                    for attack_type, count in self.attack_types.items():
                        if count > 0:
                            attack_pct = (count / self.alert_counts['attack']) * 100
                            color = CONFIG['COLORS']['RED']
                            print(f"{color}{attack_type.upper()}: {count} ({attack_pct:.1f}%){CONFIG['COLORS']['RESET']}")
                
                # Top IPs sospechosas
                suspicious_ips = Counter()
                for detection in self.recent_detections:
                    if detection['status'] in ['suspicious', 'attack']:
                        suspicious_ips[detection['src_ip']] += 1
                
                if suspicious_ips:
                    print("\nTop 5 IPs sospechosas:")
                    for ip, count in suspicious_ips.most_common(5):
                        print(f"{ip}: {count} detecciones")
                
                # Actividad reciente
                print("\nActividad reciente:")
                recent = list(reversed(list(self.recent_detections)))[:5]  # Últimas 5 detecciones
                if recent:
                    for d in recent:
                        ts = d['timestamp'].strftime('%H:%M:%S')
                        if d['status'] == 'normal':
                            color = CONFIG['COLORS']['GREEN']
                        elif d['status'] == 'suspicious':
                            color = CONFIG['COLORS']['YELLOW']
                        else:
                            color = CONFIG['COLORS']['RED']
                        
                        attack_info = f" ({d['attack_type'].upper()})" if d['attack_type'] else ""
                        print(f"{color}[{ts}] {d['src_ip']} -> {d['dst_ip']} ({d['protocol']}) - {d['score']:.4f}{attack_info}{CONFIG['COLORS']['RESET']}")
                else:
                    print("No hay actividad reciente.")
                
                print("\nPresione Ctrl+C para detener la captura")
                
                # Esperar antes de actualizar de nuevo
                time.sleep(CONFIG['UPDATE_INTERVAL'])
            
            except Exception as e:
                logger.error(f"Error mostrando estadísticas: {e}")
    
    def _print_final_stats(self):
        """Imprime estadísticas finales al terminar"""
        try:
            runtime = time.time() - self.performance_metrics['start_time']
            
            print(f"\n{CONFIG['COLORS']['BOLD']}Estadísticas finales:{CONFIG['COLORS']['RESET']}")
            print(f"Duración total: {self._format_duration(runtime)}")
            print(f"Paquetes procesados: {self.performance_metrics['packets_processed']}")
            print(f"Flujos analizados: {self.performance_metrics['flows_analyzed']}")
            print(f"Tasa de procesamiento: {self.performance_metrics['packets_processed']/runtime:.2f} paquetes/segundo")
            
            # Tiempos de procesamiento
            if self.performance_metrics['processing_times']:
                avg_proc = sum(self.performance_metrics['processing_times']) / len(self.performance_metrics['processing_times']) * 1000
                print(f"Tiempo promedio de procesamiento: {avg_proc:.2f} ms/paquete")
            
            if self.performance_metrics['detection_times']:
                avg_detect = sum(self.performance_metrics['detection_times']) / len(self.performance_metrics['detection_times']) * 1000
                print(f"Tiempo promedio de detección: {avg_detect:.2f} ms/flujo")
            
            # Distribución de alertas
            total = sum(self.alert_counts.values())
            if total > 0:
                print(f"\nDistribución de {total} alertas:")
                print(f"{CONFIG['COLORS']['GREEN']}Normal: {self.alert_counts['normal']} ({self.alert_counts['normal']/total*100:.1f}%){CONFIG['COLORS']['RESET']}")
                print(f"{CONFIG['COLORS']['YELLOW']}Sospechoso: {self.alert_counts['suspicious']} ({self.alert_counts['suspicious']/total*100:.1f}%){CONFIG['COLORS']['RESET']}")
                print(f"{CONFIG['COLORS']['RED']}Ataque: {self.alert_counts['attack']} ({self.alert_counts['attack']/total*100:.1f}%){CONFIG['COLORS']['RESET']}")
            
            # Tipos de ataques
            if self.alert_counts['attack'] > 0:
                print("\nTipos de ataques detectados:")
                for attack_type, count in self.attack_types.items():
                    if count > 0:
                        print(f"{attack_type}: {count} ({count/self.alert_counts['attack']*100:.1f}%)")
            
            # Top IPs sospechosas
            suspicious_ips = Counter(d['src_ip'] for d in self.recent_detections if d['status'] in ['suspicious', 'attack'])
            if suspicious_ips:
                print("\nTop 5 IPs sospechosas:")
                for ip, count in suspicious_ips.most_common(5):
                    print(f"{ip}: {count} detecciones")
            
            # Logs
            print(f"\nLogs detallados disponibles en: ids_detection.log")
            
        except Exception as e:
            logger.error(f"Error mostrando estadísticas finales: {e}")
    
    def _format_duration(self, seconds):
        """Formatea una duración en segundos como HH:MM:SS"""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02}:{minutes:02}:{seconds:02}"
    
    def export_stats(self, filename=None):
        """Exporta estadísticas a un archivo JSON"""
        if not filename:
            filename = f"ids_stats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            # Preparar estadísticas
            with self.flow_lock:
                active_flows = len(self.flows)
            
            stats = {
                'timestamp': datetime.datetime.now().isoformat(),
                'runtime': time.time() - self.performance_metrics['start_time'],
                'active_flows': active_flows,
                'packets_processed': self.performance_metrics['packets_processed'],
                'flows_analyzed': self.performance_metrics['flows_analyzed'],
                'alert_counts': self.alert_counts,
                'attack_types': self.attack_types,
                'recent_detections': []
            }
            
            # Convertir detecciones recientes a formato JSON serializable
            for detection in self.recent_detections:
                d = detection.copy()
                if 'timestamp' in d and isinstance(d['timestamp'], datetime.datetime):
                    d['timestamp'] = d['timestamp'].isoformat()
                if 'pattern_scores' in d:
                    d['pattern_scores'] = dict(d['pattern_scores'])
                stats['recent_detections'].append(d)
            
            # Guardar a archivo JSON
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            
            logger.info(f"Estadísticas exportadas a {filename}")
            return True
        
        except Exception as e:
            logger.error(f"Error exportando estadísticas: {e}")
            return False


def run_system(model_path, interface, duration=0, options=None):
    """
    Ejecuta el sistema de detección de intrusiones
    
    Args:
        model_path: Ruta al modelo entrenado
        interface: Interfaz de red a monitorear
        duration: Duración en segundos (0=indefinido)
        options: Opciones adicionales
    """
    try:
        # Actualizar configuración desde opciones
        if options:
            for key, value in options.items():
                if key in CONFIG:
                    if isinstance(value, dict) and isinstance(CONFIG[key], dict):
                        # Para subdiccionarios, actualizar recursivamente
                        CONFIG[key].update(value)
                    else:
                        CONFIG[key] = value
        
        # Activar colores en Windows
        if os.name == 'nt':
            os.system('color')
        
        # Inicializar monitor
        monitor = NetworkMonitor(
            model_path=model_path,
            interface=interface
        )
        
        # Iniciar captura
        monitor.start_capture()
        
        # Si se especificó una duración, ejecutar por tiempo limitado
        if duration > 0:
            try:
                # Esperar hasta que termine la duración especificada
                time.sleep(duration)
                
                # Detener captura y mostrar estadísticas finales
                monitor.stop_capture_threads()
                monitor._print_final_stats()
                
                # Exportar estadísticas si se solicitó
                if options and options.get('export_stats'):
                    monitor.export_stats()
                    
            except KeyboardInterrupt:
                print("\nCaptura interrumpida por el usuario")
                monitor.stop_capture_threads()
                monitor._print_final_stats()
        else:
            # Si no hay duración, ejecutar hasta interrupción manual
            try:
                # Mantener el programa principal en ejecución
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nCaptura interrumpida por el usuario")
                monitor.stop_capture_threads()
                monitor._print_final_stats()
    
    except Exception as e:
        logger.error(f"Error en el sistema: {e}")
        print(f"{CONFIG['COLORS']['RED']}Error en el sistema: {e}{CONFIG['COLORS']['RESET']}")
        traceback.print_exc()


def main():
    """Función principal"""
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(
        description="Sistema Avanzado de Detección de Intrusiones con Análisis Híbrido"
    )
    parser.add_argument("--model", type=str, default="model/modelo_rf.pkl", 
                        help="Ruta al modelo entrenado")
    parser.add_argument("--interface", type=str, default="Ethernet" if os.name == 'nt' else "eth0", 
                        help="Interfaz de red a monitorear")
    parser.add_argument("--duration", type=int, default=0, 
                        help="Duración del monitoreo en segundos (0=indefinido)")
    parser.add_argument("--threshold-normal", type=float, default=CONFIG['NORMAL_THRESHOLD'],
                        help=f"Umbral para tráfico normal (default: {CONFIG['NORMAL_THRESHOLD']})")
    parser.add_argument("--threshold-suspicious", type=float, default=CONFIG['SUSPICIOUS_THRESHOLD'],
                        help=f"Umbral para tráfico sospechoso (default: {CONFIG['SUSPICIOUS_THRESHOLD']})")
    parser.add_argument("--show-normal", action="store_true", 
                        help="Mostrar también el tráfico normal")
    parser.add_argument("--learning-mode", action="store_true",
                        help="Iniciar en modo aprendizaje")
    parser.add_argument("--learning-duration", type=int, default=CONFIG['LEARNING_DURATION'],
                        help="Duración del modo aprendizaje en segundos")
    parser.add_argument("--update-interval", type=int, default=CONFIG['UPDATE_INTERVAL'],
                        help="Intervalo de actualización de estadísticas en segundos")
    parser.add_argument("--export-stats", action="store_true", 
                        help="Exportar estadísticas a un archivo JSON al finalizar")
    parser.add_argument("--verbose", action="store_true", 
                        help="Mostrar información detallada de depuración")
    
    args = parser.parse_args()
    
    # Configurar nivel de log
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Actualizar configuración desde argumentos
    CONFIG['NORMAL_THRESHOLD'] = args.threshold_normal
    CONFIG['SUSPICIOUS_THRESHOLD'] = args.threshold_suspicious
    CONFIG['SHOW_NORMAL_TRAFFIC'] = args.show_normal
    CONFIG['UPDATE_INTERVAL'] = args.update_interval
    CONFIG['LEARNING_MODE'] = args.learning_mode
    CONFIG['LEARNING_DURATION'] = args.learning_duration
    
    # Verificar modelo
    if not os.path.exists(args.model):
        print(f"{CONFIG['COLORS']['RED']}Error: No se encontró el modelo en {args.model}{CONFIG['COLORS']['RESET']}")
        return
    
    # Ejecutar sistema
    try:
        run_system(args.model, args.interface, args.duration, {
            'export_stats': args.export_stats,
            'verbose': args.verbose
        })
    except KeyboardInterrupt:
        print("\nSistema detenido por el usuario")
    except Exception as e:
        print(f"{CONFIG['COLORS']['RED']}Error: {e}{CONFIG['COLORS']['RESET']}")
        traceback.print_exc()


if __name__ == "__main__":
    main()