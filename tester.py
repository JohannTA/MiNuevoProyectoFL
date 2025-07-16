#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de Envío de Emails - IDS Federado
Envía alertas críticas a johannaguinaga2004@gmail.com
Autor: Johann
Fecha: 30/06/2025
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import json

# ✅ CONFIGURACIÓN DE EMAIL
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'johannaguinaga20@gmail.com',  # Tu email remitente
    'sender_password': 'frpx cjqc ljvi wldw',  # ← CAMBIAR POR LA REAL
    'recipient_email': 'johannaguinaga2004@gmail.com',  # Email de destino
    'sender_name': 'Sistema IDS Federado'
}

def enviar_alerta_critica(detection_data):
    """Envía email de alerta crítica"""
    try:
        # ✅ CREAR MENSAJE
        confidence = detection_data.get('confidence_score', 0.0)
        source_ip = detection_data.get('source_ip', 'Desconocida')
        anomaly_type = detection_data.get('anomaly_type', 'Amenaza Desconocida')
        timestamp = detection_data.get('timestamp', datetime.datetime.now().isoformat())
        
        # Subject con emojis llamativos
        subject = f"🚨 ALERTA CRÍTICA IDS - {anomaly_type} desde {source_ip} ({confidence:.1%})"
        
        # Cuerpo del mensaje en HTML
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .alert-box {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; }}
                .details {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .footer {{ background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; }}
                .critical {{ color: #dc3545; font-weight: bold; }}
                .confidence-bar {{ background-color: #e9ecef; height: 20px; border-radius: 10px; margin: 10px 0; }}
                .confidence-fill {{ height: 100%; background: linear-gradient(90deg, #28a745, #ffc107, #dc3545); width: {confidence * 100}%; border-radius: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 ALERTA CRÍTICA DE SEGURIDAD</h1>
                    <p>Sistema IDS Federado</p>
                </div>
                
                <div class="content">
                    <div class="alert-box">
                        <strong>⚠️ ATENCIÓN:</strong> Se ha detectado una amenaza crítica que requiere atención inmediata.
                    </div>
                    
                    <h3>📊 Detalles de la Detección</h3>
                    <div class="details">
                        <strong>🎯 Tipo de Amenaza:</strong> {anomaly_type}<br>
                        <strong>📅 Fecha/Hora:</strong> {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br>
                        <strong>💻 IP de Origen:</strong> <code>{source_ip}</code><br>
                        <strong>🎯 IP de Destino:</strong> <code>{detection_data.get('destination_ip', 'N/A')}</code><br>
                        <strong>⚡ Nivel de Confianza:</strong> <span class="critical">{confidence:.1%}</span>
                    </div>
                    
                    <div class="confidence-bar">
                        <div class="confidence-fill"></div>
                    </div>
                    
                    <h3>🛡️ Información Técnica</h3>
                    <div class="details">
                        <strong>🔌 Puerto Origen:</strong> {detection_data.get('source_port', 'N/A')}<br>
                        <strong>🔌 Puerto Destino:</strong> {detection_data.get('destination_port', 'N/A')}<br>
                        <strong>📡 Protocolo:</strong> {detection_data.get('protocol', 'N/A')}<br>
                        <strong>🔍 ID de Detección:</strong> {detection_data.get('detection_id', 'N/A')}
                    </div>
                    
                    <h3>🚀 Acciones Recomendadas</h3>
                    <ul>
                        <li><strong>Revisar inmediatamente</strong> la actividad desde {source_ip}</li>
                        <li><strong>Verificar logs</strong> del firewall y sistemas relacionados</li>
                        <li><strong>Considerar bloqueo</strong> temporal de la IP si es necesario</li>
                        <li><strong>Monitorear</strong> actividad relacionada en los próximos minutos</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p><strong>📧 Email automático del Sistema IDS Federado</strong></p>
                    <p>🕐 Generado el {datetime.datetime.now().strftime('%d/%m/%Y a las %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # ✅ CREAR EMAIL
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{EMAIL_CONFIG['sender_name']} <{EMAIL_CONFIG['sender_email']}>"
        msg['To'] = EMAIL_CONFIG['recipient_email']
        msg['X-Priority'] = '1'  # Alta prioridad
        
        # Adjuntar HTML
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)
        
        # ✅ ENVIAR EMAIL
        context = ssl.create_default_context()
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls(context=context)
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            
            text = msg.as_string()
            server.sendmail(
                EMAIL_CONFIG['sender_email'],
                EMAIL_CONFIG['recipient_email'],
                text
            )
        
        print(f"✅ Email enviado exitosamente a {EMAIL_CONFIG['recipient_email']}")
        print(f"📊 Detección: {anomaly_type} desde {source_ip} (Confianza: {confidence:.1%})")
        
        return True
        
    except Exception as e:
        print(f"❌ Error enviando email: {e}")
        return False

def probar_configuracion():
    """Prueba la configuración de email"""
    try:
        context = ssl.create_default_context()
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls(context=context)
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            
        print("✅ Configuración de email correcta")
        return True
        
    except Exception as e:
        print(f"❌ Error en configuración: {e}")
        return False

def enviar_email_prueba():
    """Envía un email de prueba"""
    test_detection = {
        'detection_id': f'TEST-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}',
        'timestamp': datetime.datetime.now().isoformat(),
        'anomaly_type': 'Test - Simulación de Ataque',
        'confidence_score': 0.95,
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'destination_port': 80,
        'protocol': 'TCP'
    }
    
    return enviar_alerta_critica(test_detection)

def main():
    """Función principal"""
    print("🔧 Sistema de Envío de Emails - IDS Federado")
    print(f"📧 Destinatario: {EMAIL_CONFIG['recipient_email']}")
    print(f"📤 Remitente: {EMAIL_CONFIG['sender_email']}")
    print("-" * 50)
    
    # Probar configuración
    print("🔍 Probando configuración SMTP...")
    if not probar_configuracion():
        print("❌ Error en configuración. Verifica credenciales.")
        return
    
    # Menú de opciones
    while True:
        print("\n📋 Opciones:")
        print("1. Enviar email de prueba")
        print("2. Enviar alerta personalizada")
        print("3. Salir")
        
        opcion = input("\n🔸 Selecciona una opción (1-3): ").strip()
        
        if opcion == "1":
            print("\n📧 Enviando email de prueba...")
            if enviar_email_prueba():
                print("✅ Email de prueba enviado correctamente")
            else:
                print("❌ Error enviando email de prueba")
                
        elif opcion == "2":
            print("\n📝 Crear alerta personalizada:")
            
            # Solicitar datos
            source_ip = input("IP de origen (ej: 192.168.1.100): ").strip() or "192.168.1.100"
            anomaly_type = input("Tipo de amenaza (ej: DDoS Attack): ").strip() or "Amenaza Crítica"
            confidence = float(input("Nivel de confianza (0.5-1.0): ").strip() or "0.85")
            
            # Crear detección personalizada
            custom_detection = {
                'detection_id': f'CUSTOM-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}',
                'timestamp': datetime.datetime.now().isoformat(),
                'anomaly_type': anomaly_type,
                'confidence_score': confidence,
                'source_ip': source_ip,
                'destination_ip': '192.168.1.1',
                'source_port': 12345,
                'destination_port': 80,
                'protocol': 'TCP'
            }
            
            print(f"\n📧 Enviando alerta: {anomaly_type} desde {source_ip}...")
            if enviar_alerta_critica(custom_detection):
                print("✅ Alerta enviada correctamente")
            else:
                print("❌ Error enviando alerta")
                
        elif opcion == "3":
            print("👋 ¡Hasta luego!")
            break
            
        else:
            print("❌ Opción inválida")

if __name__ == "__main__":
    main()