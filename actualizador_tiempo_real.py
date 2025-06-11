import asyncio
import json
import time
from datetime import datetime
from db.db import obtener_conexion
from psycopg2.extras import RealDictCursor
import logging

logger = logging.getLogger(__name__)

class ActualizadorTiempoReal:
    """Actualiza datos del dashboard en tiempo real"""
    
    def __init__(self):
        self.cache_stats = {}
        self.last_update = 0
        self.update_interval = 5  # 5 segundos
        
    def get_real_time_stats(self):
        """Obtiene estadísticas en tiempo real"""
        current_time = time.time()
        
        # Cache para evitar consultas excesivas
        if current_time - self.last_update < self.update_interval:
            return self.cache_stats
        
        conn = None
        try:
            conn = obtener_conexion()
            if not conn:
                return self.cache_stats
            
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Estadísticas rápidas
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_detecciones,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') as detecciones_1h,
                        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as detecciones_24h,
                        COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) as alertas_criticas,
                        COUNT(DISTINCT client_id) as clientes_detectando
                    FROM detections
                """)
                
                stats = cursor.fetchone()
                
                # Distribución por severidad (última hora)
                cursor.execute("""
                    SELECT severity, COUNT(*) as count
                    FROM detections 
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                    GROUP BY severity
                """)
                
                severidad_1h = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Tipos de ataque (última hora)
                cursor.execute("""
                    SELECT anomaly_type, COUNT(*) as count
                    FROM detections 
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                      AND anomaly_type IS NOT NULL
                    GROUP BY anomaly_type
                    ORDER BY count DESC
                    LIMIT 5
                """)
                
                tipos_ataque_1h = [dict(row) for row in cursor.fetchall()]
                
                # Actividad por minuto (última hora)
                cursor.execute("""
                    SELECT 
                        EXTRACT(EPOCH FROM date_trunc('minute', timestamp))::bigint as minute_timestamp,
                        COUNT(*) as count,
                        COUNT(*) FILTER (WHERE severity = 'critical') as critical_count
                    FROM detections 
                    WHERE timestamp >= NOW() - INTERVAL '1 hour'
                    GROUP BY date_trunc('minute', timestamp)
                    ORDER BY minute_timestamp
                """)
                
                actividad_minuto = [dict(row) for row in cursor.fetchall()]
                
                self.cache_stats = {
                    'timestamp': current_time,
                    'resumen': dict(stats),
                    'severidad_1h': severidad_1h,
                    'tipos_ataque_1h': tipos_ataque_1h,
                    'actividad_minuto': actividad_minuto
                }
                
                self.last_update = current_time
                
        except Exception as e:
            logger.error(f"Error obteniendo stats tiempo real: {e}")
        finally:
            if conn:
                conn.close()
        
        return self.cache_stats

# Instancia global
actualizador_tiempo_real = ActualizadorTiempoReal()