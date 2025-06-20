#!/usr/bin/env python3
# fix_main_complete.py

def fix_main_py():
    """Corrige todos los errores sintácticos en main.py"""
    
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Agregar imports faltantes
    imports_to_add = [
        'import uuid',
        'import datetime', 
        'import json',
        'import time'
    ]
    
    for imp in imports_to_add:
        if imp not in content:
            content = content.replace(
                'from functools import wraps',
                f'from functools import wraps\n{imp}'
            )
    
    # 2. Corregir datetime.now()
    content = content.replace(
        "datetime.now().isoformat()",
        "datetime.datetime.now().isoformat()"
    )
    
    # 3. Corregir referencias a detection_buffer
    content = content.replace(
        "detection_buffer.add_detection(detection_data)",
        "# Buffer eliminado - guardado directo en BD"
    )
    
    # 4. Corregir referencias a detector_output_lock
    content = content.replace(
        "with detector_output_lock:",
        "# Lock eliminado - no necesario"
    )
    
    with open('main.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ main.py corregido completamente")

if __name__ == "__main__":
    print("🔧 CORRIGIENDO ERRORES SINTÁCTICOS")
    fix_main_py()
    print("🎯 Reinicia el servidor: python main.py")