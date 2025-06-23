#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGENTE AUTOMÁTICO DE CORRECCIÓN - SISTEMA IDS FEDERADO
======================================================
Analiza y corrige automáticamente errores en main.py
Autor: GitHub Copilot Assistant
Versión: 1.0
"""

import re
import os
import sys
import time
import json
import shutil
from datetime import datetime
from pathlib import Path

class IDSAutoFixer:
    """Agente automático para corregir errores en el sistema IDS"""
    
    def __init__(self, project_path='.'):
        self.project_path = Path(project_path)
        self.main_file = self.project_path / 'main.py'
        self.backup_dir = self.project_path / 'backup_auto'
        self.errors_found = []
        self.fixes_applied = []
        
        # Crear directorio de backup
        self.backup_dir.mkdir(exist_ok=True)
        
        print("🤖 AGENTE AUTOMÁTICO DE CORRECCIÓN INICIADO")
        print("=" * 60)
    
    def create_backup(self):
        """Crea backup del archivo antes de modificar"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"main_backup_{timestamp}.py"
        
        try:
            shutil.copy2(self.main_file, backup_file)
            print(f"✅ Backup creado: {backup_file.name}")
            return backup_file
        except Exception as e:
            print(f"❌ Error creando backup: {e}")
            return None
    
    def analyze_code(self):
        """Analiza el código y detecta errores"""
        print("\n🔍 ANALIZANDO CÓDIGO...")
        
        with open(self.main_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        errors = []
        
        # 1. Error de indentación línea 919
        if 'lines = detector_output_queue[since:] if since < len(detector_output_queue) else []' in content:
            # Buscar si está mal indentada
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                if 'lines = detector_output_queue[since:] if since < len(detector_output_queue) else []' in line:
                    if line.startswith('            '):  # 12 espacios = mal
                        errors.append({
                            'type': 'indentation_error',
                            'line': i,
                            'description': 'Indentación incorrecta en get_detector_output',
                            'severity': 'critical'
                        })
        
        # 2. Datetime triple
        if 'datetime.datetime.datetime.now()' in content:
            errors.append({
                'type': 'datetime_triple',
                'description': 'Referencias a datetime.datetime.datetime.now()',
                'severity': 'critical'
            })
        
        # 3. Variables no definidas
        if 'start_time if \'start_time\' in globals()' in content and 'start_time = time.time()' not in content:
            errors.append({
                'type': 'undefined_variable',
                'description': 'Variable start_time no definida',
                'severity': 'high'
            })
        
        # 4. Imports faltantes
        imports_needed = ['import time', 'import uuid', 'import json']
        for imp in imports_needed:
            if imp not in content:
                errors.append({
                    'type': 'missing_import',
                    'description': f'Import faltante: {imp}',
                    'severity': 'medium'
                })
        
        # 5. Filtros duplicados
        time_ago_count = content.count("@app.template_filter('time_ago')")
        if time_ago_count > 1:
            errors.append({
                'type': 'duplicate_filter',
                'description': f'Filtro time_ago duplicado {time_ago_count} veces',
                'severity': 'medium'
            })
        
        # 6. Referencias a buffer eliminado
        if '"buffer": detection_buffer.get_stats()' in content:
            errors.append({
                'type': 'obsolete_reference',
                'description': 'Referencias a detection_buffer eliminado',
                'severity': 'high'
            })
        
        self.errors_found = errors
        return errors
    
    def fix_indentation_error(self, content):
        """Corrige error de indentación línea 919"""
        print("🔧 Corrigiendo error de indentación...")
        
        lines = content.split('\n')
        fixed = False
        
        for i, line in enumerate(lines):
            if 'lines = detector_output_queue[since:] if since < len(detector_output_queue) else []' in line:
                if line.startswith('            '):  # 12 espacios
                    lines[i] = '        ' + line.strip()  # 8 espacios
                    fixed = True
                    self.fixes_applied.append("✅ Indentación corregida en get_detector_output")
        
        return '\n'.join(lines), fixed
    
    def fix_datetime_triple(self, content):
        """Corrige datetime.datetime.datetime.now()"""
        print("🔧 Corrigiendo datetime triple...")
        
        original_content = content
        content = content.replace(
            'datetime.datetime.datetime.now()',
            'datetime.datetime.now()'
        )
        
        if content != original_content:
            self.fixes_applied.append("✅ datetime.datetime.datetime.now() corregido")
            return content, True
        
        return content, False
    
    def fix_undefined_variables(self, content):
        """Corrige variables no definidas"""
        print("🔧 Agregando variables faltantes...")
        
        fixes = []
        
        # Agregar start_time si no existe
        if 'start_time = time.time()' not in content:
            # Buscar lugar para insertar
            if 'app_start_time = time.time()' in content:
                content = content.replace(
                    'app_start_time = time.time()',
                    'start_time = time.time()\napp_start_time = time.time()'
                )
                fixes.append("✅ Variable start_time agregada")
        
        # Agregar detector_output_queue si no existe
        if 'detector_output_queue = []' not in content:
            # Insertar después de federado_stats
            federado_stats_end = content.find('}', content.find('federado_stats = {'))
            if federado_stats_end != -1:
                insert_point = content.find('\n', federado_stats_end) + 1
                variables_to_add = """
# Variables globales para salida del detector
detector_output_queue = []
"""
                content = content[:insert_point] + variables_to_add + content[insert_point:]
                fixes.append("✅ Variable detector_output_queue agregada")
        
        self.fixes_applied.extend(fixes)
        return content, len(fixes) > 0
    
    def fix_missing_imports(self, content):
        """Agrega imports faltantes"""
        print("🔧 Agregando imports faltantes...")
        
        imports_to_add = []
        
        if 'import time' not in content:
            imports_to_add.append('import time')
        
        if 'import uuid' not in content:
            imports_to_add.append('import uuid')
        
        if 'import json' not in content:
            imports_to_add.append('import json')
        
        if imports_to_add:
            # Insertar después de import threading
            for imp in imports_to_add:
                content = content.replace(
                    'import threading',
                    f'import threading\n{imp}'
                )
            
            self.fixes_applied.append(f"✅ Imports agregados: {', '.join(imports_to_add)}")
            return content, True
        
        return content, False
    
    def fix_duplicate_filters(self, content):
        """Elimina filtros duplicados"""
        print("🔧 Eliminando filtros duplicados...")
        
        # Buscar todas las definiciones de time_ago
        time_ago_pattern = r"@app\.template_filter\('time_ago'\)\ndef time_ago\(value\):.*?(?=@app\.template_filter|def [^_]|@app\.route|if __name__|$)"
        matches = list(re.finditer(time_ago_pattern, content, re.DOTALL))
        
        if len(matches) > 1:
            # Eliminar todas menos la última
            offset = 0
            for match in matches[:-1]:
                start = match.start() + offset
                end = match.end() + offset
                replacement = "# time_ago duplicado eliminado\n"
                content = content[:start] + replacement + content[end:]
                offset += len(replacement) - (end - start)
            
            self.fixes_applied.append(f"✅ {len(matches)-1} filtros time_ago duplicados eliminados")
            return content, True
        
        return content, False
    
    def fix_obsolete_references(self, content):
        """Elimina referencias obsoletas"""
        print("🔧 Eliminando referencias obsoletas...")
        
        fixes = []
        
        # Eliminar referencias a detection_buffer
        if '"buffer": detection_buffer.get_stats()' in content:
            content = content.replace(
                '"buffer": detection_buffer.get_stats()',
                '# "buffer": detection_buffer.get_stats()  # Buffer eliminado'
            )
            fixes.append("✅ Referencias a detection_buffer eliminadas")
        
        # Eliminar buffer_info references
        if 'buffer_info = detection_buffer.get_stats()' in content:
            content = content.replace(
                'buffer_info = detection_buffer.get_stats()',
                'buffer_info = {"buffer_size": 0, "save_rate": 100.0, "total_buffered": 0}'
            )
            fixes.append("✅ buffer_info corregido")
        
        self.fixes_applied.extend(fixes)
        return content, len(fixes) > 0
    
    def apply_fixes(self):
        """Aplica todas las correcciones automáticamente"""
        print("\n🔧 APLICANDO CORRECCIONES...")
        
        # Crear backup primero
        backup = self.create_backup()
        if not backup:
            print("❌ No se pudo crear backup. Abortando.")
            return False
        
        try:
            with open(self.main_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            total_fixes = 0
            
            # Aplicar cada corrección
            content, fixed = self.fix_indentation_error(content)
            if fixed: total_fixes += 1
            
            content, fixed = self.fix_datetime_triple(content)
            if fixed: total_fixes += 1
            
            content, fixed = self.fix_undefined_variables(content)
            if fixed: total_fixes += 1
            
            content, fixed = self.fix_missing_imports(content)
            if fixed: total_fixes += 1
            
            content, fixed = self.fix_duplicate_filters(content)
            if fixed: total_fixes += 1
            
            content, fixed = self.fix_obsolete_references(content)
            if fixed: total_fixes += 1
            
            # Guardar archivo corregido
            if content != original_content:
                with open(self.main_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"\n✅ CORRECCIONES APLICADAS: {total_fixes}")
                return True
            else:
                print("\n ℹ️  No se encontraron errores que corregir")
                return True
                
        except Exception as e:
            print(f"\n❌ Error aplicando correcciones: {e}")
            # Restaurar backup
            if backup.exists():
                shutil.copy2(backup, self.main_file)
                print("🔄 Backup restaurado")
            return False
    
    def generate_report(self):
        """Genera reporte de correcciones"""
        print("\n📋 REPORTE DE CORRECCIONES")
        print("=" * 40)
        
        print(f"🔍 Errores encontrados: {len(self.errors_found)}")
        for error in self.errors_found:
            severity_icon = "🔴" if error['severity'] == 'critical' else "🟡" if error['severity'] == 'high' else "🟢"
            print(f"   {severity_icon} {error['description']}")
        
        print(f"\n✅ Correcciones aplicadas: {len(self.fixes_applied)}")
        for fix in self.fixes_applied:
            print(f"   {fix}")
        
        print(f"\n📁 Backup guardado en: {self.backup_dir}")
        
        # Guardar reporte en archivo
        report = {
            'timestamp': datetime.now().isoformat(),
            'errors_found': self.errors_found,
            'fixes_applied': self.fixes_applied,
            'total_errors': len(self.errors_found),
            'total_fixes': len(self.fixes_applied)
        }
        
        report_file = self.backup_dir / f"correction_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Reporte detallado guardado: {report_file.name}")
    
    def run(self):
        """Ejecuta el proceso completo de corrección"""
        print("🚀 INICIANDO PROCESO DE CORRECCIÓN AUTOMÁTICA")
        print(f"📂 Proyecto: {self.project_path.absolute()}")
        print(f"📄 Archivo: {self.main_file.name}")
        
        # Verificar que el archivo existe
        if not self.main_file.exists():
            print(f"❌ Error: {self.main_file} no encontrado")
            return False
        
        # Analizar código
        errors = self.analyze_code()
        
        if not errors:
            print("\n🎉 ¡CÓDIGO SIN ERRORES DETECTADOS!")
            return True
        
        print(f"\n⚠️  ERRORES DETECTADOS: {len(errors)}")
        for error in errors:
            print(f"   • {error['description']} ({error['severity']})")
        
        # Preguntar si aplicar correcciones
        print(f"\n❓ ¿Aplicar correcciones automáticamente? (y/n): ", end="")
        response = input().lower().strip()
        
        if response in ['y', 'yes', 'si', 's']:
            success = self.apply_fixes()
            self.generate_report()
            
            if success:
                print("\n🎉 PROCESO COMPLETADO EXITOSAMENTE")
                print("🔄 Reinicia main.py para verificar las correcciones:")
                print("   python main.py")
                return True
            else:
                print("\n❌ PROCESO FALLÓ")
                return False
        else:
            print("\n🛑 Proceso cancelado por el usuario")
            return False

def main():
    """Función principal del agente automático"""
    print("🤖 AGENTE AUTOMÁTICO DE CORRECCIÓN - SISTEMA IDS FEDERADO")
    print("=" * 65)
    print("Este agente analizará y corregirá automáticamente los errores")
    print("en tu archivo main.py")
    print("=" * 65)
    
    # Crear instancia del agente
    fixer = IDSAutoFixer()
    
    # Ejecutar proceso de corrección
    success = fixer.run()
    
    if success:
        print("\n🎯 SIGUIENTE PASO:")
        print("   Ejecuta: python main.py")
        print("   Verifica que no haya errores en la consola")
        
        return 0
    else:
        print("\n❌ El proceso de corrección falló")
        print("   Revisa los errores manualmente")
        return 1

if __name__ == "__main__":
    sys.exit(main())