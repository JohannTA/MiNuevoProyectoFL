#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Función Simple para Enviar Correos de Alerta
Solo llamar: enviarcorreoalerta()
"""

import smtplib
import ssl
from email.mime.text import MIMEText
import datetime

def enviarcorreoalerta():
    """Función simple para enviar alerta por correo - Solo llamar esta función"""
    try:
        # ✅ CONFIGURACIÓN (BASADA EN TU ALERTA_EXTERNA.PY QUE FUNCIONA)
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        sender_email = 'johannaguinaga20@gmail.com'
        sender_password = 'sbxs yalf rlos nrjr'
        recipient_email = 'johannaguinaga2004@gmail.com'
        
        # ✅ TIMESTAMP ACTUAL
        now = datetime.datetime.now()
        
        # ✅ MENSAJE SIMPLE
        subject = f"🚨 ALERTA IDS - {now.strftime('%H:%M:%S')}"
        
        body = f"""
🚨 ALERTA DEL SISTEMA IDS FEDERADO

📅 Fecha/Hora: {now.strftime('%d/%m/%Y %H:%M:%S')}
🔍 Timestamp: {now.isoformat()}
⚡ Tipo: Alerta Crítica
🎯 Sistema: IDS Federado
⚙️ Generado automáticamente

🕐 Hora exacta: {now.strftime('%H:%M:%S.%f')[:-3]}

Esta alerta fue generada automáticamente por el sistema.
"""
        
        # ✅ CREAR Y ENVIAR EMAIL
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['X-Priority'] = '1'
        
        context = ssl.create_default_context()
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        
        print(f"✅ Correo enviado: {now.strftime('%H:%M:%S')}")
        return True
        
    except Exception as e:
        print(f"❌ Error enviando correo: {e}")
        return False

# Para poder importar fácilmente
__all__ = ['enviarcorreoalerta']
 # Llamar automáticamente al importar este módulo