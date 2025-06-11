#!/usr/bin/env python3
"""
Sistema Completo IDS Federado
----------------------------
Ejecuta todos los componentes integrados
"""

import subprocess
import threading
import time
import sys
import os
from pathlib import Path
import signal
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SistemaCompleto:
    """Gestor del sistema completo"""
    
    def __init__(self):
        self.procesos = []
        self.running = False
        
    def ejecutar_componente(self, comando, nombre, directorio=None):
        """Ejecuta un componente en proceso separado"""
        try:
            print(f"🚀 Iniciando {nombre}...")
            
            proceso = subprocess.Popen(
                comando,
                shell=True,
                cwd=directorio or os.getcwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.procesos.append((proceso, nombre))
            print(f"✅ {nombre} iniciado (PID: {proceso.pid})")
            
            # Hilo para mostrar salida
            def mostrar_salida():
                for line in iter(proceso.stdout.readline, ''):
                    if line.strip():
                        print(f"[{nombre}] {line.strip()}")
            
            threading.Thread(target=mostrar_salida, daemon=True).start()
            
            return proceso
            
        except Exception as e:
            print(f"❌ Error iniciando {nombre}: {e}")
            return None
    
    def iniciar_sistema(self):
        """Inicia todo el sistema"""
        print("🛡️  INICIANDO SISTEMA IDS FEDERADO COMPLETO")
        print("=" * 60)
        
        try:
            # 1. Limpiar y preparar BD
            print("\n📋 PASO 1: Preparando base de datos...")
            resultado_bd = subprocess.run([
                sys.executable, "limpiar_bd.py"
            ], capture_output=True, text=True)
            
            if resultado_bd.returncode == 0:
                print("✅ Base de datos preparada")
            else:
                print("❌ Error preparando BD:", resultado_bd.stderr)
                return False
            
            time.sleep(2)
            
            # 2. Aplicación Web Flask
            print("\n🌐 PASO 2: Iniciando aplicación web...")
            self.ejecutar_componente(
                f"{sys.executable} main.py",
                "WebApp-Flask"
            )
            time.sleep(5)
            
            # 3. Servidor Federado
            print("\n🔗 PASO 3: Iniciando servidor federado...")
            self.ejecutar_componente(
                f"{sys.executable} servidor_federado.py --host 0.0.0.0 --port 5000",
                "Servidor-Federado"
            )
            time.sleep(5)
            
            # 4. Detector Principal
            print("\n🔍 PASO 4: Iniciando detector principal...")
            self.ejecutar_componente(
                f"{sys.executable} detector_integrado.py --interface Wi-Fi --client-id 1",
                "Detector-Principal"
            )
            time.sleep(3)
            
            # 5. Cliente Federado (opcional)
            print("\n📡 PASO 5: Iniciando cliente federado...")
            self.ejecutar_componente(
                f"{sys.executable} cliente_federado.py --server ws://localhost:5000 --name IDS-Principal --interface Wi-Fi",
                "Cliente-Federado"
            )
            
            self.running = True
            self.mostrar_estado_sistema()
            
            return True
            
        except Exception as e:
            logger.error(f"Error iniciando sistema: {e}")
            return False
    
    def mostrar_estado_sistema(self):
        """Muestra el estado del sistema"""
        print("\n" + "=" * 60)
        print("🎉 ¡SISTEMA COMPLETAMENTE INICIADO!")
        print("=" * 60)
        print("🌐 Dashboard Web: http://localhost:5000")
        print("   👤 Usuario: admin")
        print("   🔑 Contraseña: admin123")
        print()
        print("🔗 Servidor Federado: ws://0.0.0.0:5000")
        print("🔍 Detector: Capturando en Wi-Fi")
        print("📊 Base de Datos: PostgreSQL activa")
        print()
        print("📋 COMPONENTES ACTIVOS:")
        for proceso, nombre in self.procesos:
            estado = "🟢 Activo" if proceso.poll() is None else "🔴 Inactivo"
            print(f"   • {nombre}: {estado} (PID: {proceso.pid})")
        
        print(f"\n⚠️  Presiona Ctrl+C para detener todo el sistema")
        print("=" * 60)
    
    def detener_sistema(self):
        """Detiene todos los componentes"""
        print("\n🛑 DETENIENDO SISTEMA...")
        
        for proceso, nombre in self.procesos:
            try:
                if proceso.poll() is None:
                    print(f"   Deteniendo {nombre}...")
                    proceso.terminate()
                    
                    # Esperar terminación
                    try:
                        proceso.wait(timeout=5)
                        print(f"   ✅ {nombre} detenido")
                    except subprocess.TimeoutExpired:
                        print(f"   🔥 Forzando cierre de {nombre}...")
                        proceso.kill()
                        proceso.wait()
                        print(f"   ✅ {nombre} forzado a cerrar")
                        
            except Exception as e:
                print(f"   ❌ Error deteniendo {nombre}: {e}")
        
        self.running = False
        print("✅ Sistema detenido completamente")
    
    def monitorear_procesos(self):
        """Monitorea el estado de los procesos"""
        while self.running:
            try:
                time.sleep(30)  # Verificar cada 30 segundos
                
                procesos_activos = 0
                for proceso, nombre in self.procesos:
                    if proceso.poll() is None:
                        procesos_activos += 1
                    else:
                        print(f"⚠️  {nombre} ha terminado")
                
                if procesos_activos == 0:
                    print("🛑 Todos los procesos han terminado")
                    self.running = False
                    break
                    
            except Exception as e:
                logger.error(f"Error monitoreando: {e}")
                time.sleep(10)
    
    def ejecutar(self):
        """Ejecuta el sistema completo"""
        try:
            # Configurar manejo de señales
            def signal_handler(sig, frame):
                print(f"\n🛑 Señal {sig} recibida...")
                self.detener_sistema()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Iniciar sistema
            if self.iniciar_sistema():
                # Iniciar monitor en hilo separado
                monitor_thread = threading.Thread(target=self.monitorear_procesos, daemon=True)
                monitor_thread.start()
                
                # Mantener activo el programa principal
                while self.running:
                    time.sleep(1)
            else:
                print("❌ No se pudo iniciar el sistema")
                
        except KeyboardInterrupt:
            print("\n🛑 Interrupción recibida...")
        except Exception as e:
            print(f"❌ Error ejecutando sistema: {e}")
        finally:
            self.detener_sistema()

if __name__ == "__main__":
    print("🛡️  SISTEMA IDS FEDERADO v1.0")
    print("Iniciando sistema completo...")
    print("-" * 40)
    
    sistema = SistemaCompleto()
    sistema.ejecutar()