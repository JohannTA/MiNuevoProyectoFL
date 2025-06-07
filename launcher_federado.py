#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Launcher para Sistema Federado de Detección de Intrusiones
----------------------------------------------------------
Facilita el lanzamiento del servidor y múltiples clientes
Autor: Johann
Fecha: 2025-06-06
Versión: 1.0
"""

import argparse
import subprocess
import time
import sys
import os
from pathlib import Path
import json

def launch_server(args):
    """Lanza el servidor federado"""
    print("Iniciando servidor federado...")
    
    cmd = [
        sys.executable, "servidor_federado.py",
        "--host", args.host,
        "--port", str(args.port),
        "--model", args.model,
        "--min-clients", str(args.min_clients),
        "--aggregation-interval", str(args.aggregation_interval)
    ]
    
    return subprocess.Popen(cmd)

def launch_client(name, location, interface, server_url, model_path):
    """Lanza un cliente federado"""
    print(f"Iniciando cliente: {name}")
    
    cmd = [
        sys.executable, "cliente_federado.py",
        "--server", server_url,
        "--name", name,
        "--location", location,
        "--interface", interface,
        "--model", model_path
    ]
    
    return subprocess.Popen(cmd)

def create_demo_config():
    """Crea una configuración de demostración"""
    config = {
        "server": {
            "host": "localhost",
            "port": 8765,
            "model": "model/modelo_rf.pkl"
        },
        "clients": [
            {
                "name": "IDS-Office",
                "location": "Oficina Principal",
                "interface": "Ethernet"
            },
            {
                "name": "IDS-Datacenter", 
                "location": "Centro de Datos",
                "interface": "Ethernet 2"
            },
            {
                "name": "IDS-Remote",
                "location": "Sucursal Remota", 
                "interface": "WiFi"
            }
        ]
    }
    
    with open("config_federado.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("Configuración de demo creada: config_federado.json")
    return config

def main():
    parser = argparse.ArgumentParser(description="Launcher para Sistema Federado IDS")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # Comando servidor
    server_parser = subparsers.add_parser("server", help="Iniciar solo servidor")
    server_parser.add_argument("--host", default="localhost", help="Host del servidor")
    server_parser.add_argument("--port", type=int, default=8765, help="Puerto del servidor")
    server_parser.add_argument("--model", default="model/modelo_rf.pkl", help="Modelo inicial")
    server_parser.add_argument("--min-clients", type=int, default=2, help="Mínimo clientes")
    server_parser.add_argument("--aggregation-interval", type=int, default=300, help="Intervalo agregación")
    
    # Comando cliente
    client_parser = subparsers.add_parser("client", help="Iniciar solo cliente")
    client_parser.add_argument("--server", default="ws://localhost:8765", help="URL del servidor")
    client_parser.add_argument("--name", required=True, help="Nombre del cliente")
    client_parser.add_argument("--location", default="Unknown", help="Ubicación")
    client_parser.add_argument("--interface", default="Ethernet", help="Interfaz de red")
    client_parser.add_argument("--model", default="model/modelo_rf.pkl", help="Modelo local")
    
    # Comando demo
    demo_parser = subparsers.add_parser("demo", help="Iniciar demo completo")
    demo_parser.add_argument("--config", default="config_federado.json", help="Archivo de configuración")
    demo_parser.add_argument("--create-config", action="store_true", help="Crear config de demo")
    
    # Comando all
    all_parser = subparsers.add_parser("all", help="Iniciar servidor + clientes")
    all_parser.add_argument("--num-clients", type=int, default=3, help="Número de clientes")
    all_parser.add_argument("--host", default="localhost", help="Host del servidor")
    all_parser.add_argument("--port", type=int, default=8765, help="Puerto del servidor")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    processes = []
    
    try:
        if args.command == "server":
            # Solo servidor
            server_proc = launch_server(args)
            processes.append(server_proc)
            print(f"Servidor iniciado en {args.host}:{args.port}")
            
        elif args.command == "client":
            # Solo cliente
            client_proc = launch_client(
                args.name, args.location, args.interface, 
                args.server, args.model
            )
            processes.append(client_proc)
            print(f"Cliente {args.name} conectando a {args.server}")
            
        elif args.command == "demo":
            # Demo completo
            if args.create_config:
                create_demo_config()
                return
            
            # Cargar configuración
            if not Path(args.config).exists():
                print(f"Archivo de configuración no encontrado: {args.config}")
                print("Use --create-config para crear uno de ejemplo")
                return
            
            with open(args.config, "r") as f:
                config = json.load(f)
            
            # Iniciar servidor
            server_args = argparse.Namespace(**config["server"])
            server_args.min_clients = 2
            server_args.aggregation_interval = 300
            
            server_proc = launch_server(server_args)
            processes.append(server_proc)
            
            print("Esperando que el servidor se inicie...")
            time.sleep(5)
            
            # Iniciar clientes
            server_url = f"ws://{config['server']['host']}:{config['server']['port']}"
            model_path = config['server']['model']
            
            for client_config in config["clients"]:
                client_proc = launch_client(
                    client_config["name"],
                    client_config["location"], 
                    client_config["interface"],
                    server_url,
                    model_path
                )
                processes.append(client_proc)
                time.sleep(2)  # Espaciar conexiones
            
        elif args.command == "all":
            # Servidor + múltiples clientes
            server_proc = launch_server(args)
            processes.append(server_proc)
            
            print("Esperando que el servidor se inicie...")
            time.sleep(5)
            
            # Crear clientes automáticamente
            server_url = f"ws://{args.host}:{args.port}"
            
            for i in range(args.num_clients):
                client_name = f"IDS-Client-{i+1}"
                location = f"Location-{i+1}"
                interface = "Ethernet" if os.name == 'nt' else f"eth{i}"
                
                client_proc = launch_client(
                    client_name, location, interface,
                    server_url, "model/modelo_rf.pkl"
                )
                processes.append(client_proc)
                time.sleep(2)
        
        # Esperar a que terminen los procesos
        print("\nSistema federado iniciado")
        print("Presione Ctrl+C para detener todos los procesos")
        
        try:
            while True:
                time.sleep(1)
                # Verificar si algún proceso terminó
                for proc in processes[:]:
                    if proc.poll() is not None:
                        print(f"Proceso terminado con código: {proc.returncode}")
                        processes.remove(proc)
                
                if not processes:
                    print("Todos los procesos han terminado")
                    break
                    
        except KeyboardInterrupt:
            print("\nDeteniendo todos los procesos...")
            
    except Exception as e:
        print(f"Error: {e}")
        
    finally:
        # Terminar todos los procesos
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                proc.kill()
        
        print("Sistema federado detenido")


if __name__ == "__main__":
    main()