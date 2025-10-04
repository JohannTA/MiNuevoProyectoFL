"""
Script para extraer el esquema completo de la base de datos PostgreSQL
Genera documentación detallada de toda la estructura de la BD
"""

import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
from collections import defaultdict

class DatabaseSchemaExtractor:
    def __init__(self, host, database, user, password, port="5432"):
        """Inicializa la conexión a la base de datos"""
        self.connection_params = {
            'host': host,
            'database': database,
            'user': user,
            'password': password,
            'port': port
        }
        self.conn = None
        self.schema = {
            'metadata': {},
            'tables': {},
            'views': {},
            'functions': {},
            'triggers': {},
            'sequences': {},
            'indexes': {},
            'constraints': {},
            'relationships': []
        }
    
    def connect(self):
        """Establece conexión con la base de datos"""
        try:
            self.conn = psycopg2.connect(**self.connection_params)
            print(f"✅ Conexión exitosa a {self.connection_params['database']}")
            return True
        except Exception as e:
            print(f"❌ Error de conexión: {e}")
            return False
    
    def disconnect(self):
        """Cierra la conexión"""
        if self.conn:
            self.conn.close()
            print("🔌 Conexión cerrada")
    
    def extract_metadata(self):
        """Extrae metadatos generales de la base de datos"""
        print("\n📊 Extrayendo metadatos...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Versión de PostgreSQL
            cursor.execute("SELECT version();")
            pg_version = cursor.fetchone()['version']
            
            # Información de la base de datos
            cursor.execute("""
                SELECT 
                    pg_database.datname as database_name,
                    pg_size_pretty(pg_database_size(pg_database.datname)) as size,
                    pg_encoding_to_char(pg_database.encoding) as encoding,
                    pg_database.datcollate as collation
                FROM pg_database
                WHERE datname = current_database();
            """)
            db_info = cursor.fetchone()
            
            # Contar objetos
            cursor.execute("""
                SELECT 
                    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public') as total_tables,
                    (SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'public') as total_views,
                    (SELECT COUNT(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace) as total_functions,
                    (SELECT COUNT(*) FROM pg_trigger) as total_triggers,
                    (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public') as total_indexes
            """)
            counts = cursor.fetchone()
            
            self.schema['metadata'] = {
                'extraction_date': datetime.now().isoformat(),
                'postgresql_version': pg_version,
                'database_info': dict(db_info),
                'object_counts': dict(counts)
            }
            
            print(f"   • Database: {db_info['database_name']}")
            print(f"   • Size: {db_info['size']}")
            print(f"   • Tables: {counts['total_tables']}")
            print(f"   • Views: {counts['total_views']}")
            print(f"   • Functions: {counts['total_functions']}")
    
    def extract_tables(self):
        """Extrae información detallada de todas las tablas"""
        print("\n📋 Extrayendo tablas...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Obtener lista de tablas
            cursor.execute("""
                SELECT 
                    table_name,
                    table_type
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name;
            """)
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table['table_name']
                print(f"   📄 Procesando: {table_name}")
                
                # Columnas de la tabla
                cursor.execute("""
                    SELECT 
                        column_name,
                        data_type,
                        character_maximum_length,
                        numeric_precision,
                        numeric_scale,
                        is_nullable,
                        column_default,
                        ordinal_position
                    FROM information_schema.columns
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                    ORDER BY ordinal_position;
                """, (table_name,))
                columns = cursor.fetchall()
                
                # Primary Key
                cursor.execute("""
                    SELECT a.attname
                    FROM pg_index i
                    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                    WHERE i.indrelid = %s::regclass
                    AND i.indisprimary;
                """, (table_name,))
                pk = cursor.fetchall()
                
                # Foreign Keys
                cursor.execute("""
                    SELECT
                        tc.constraint_name,
                        kcu.column_name,
                        ccu.table_name AS foreign_table_name,
                        ccu.column_name AS foreign_column_name,
                        rc.update_rule,
                        rc.delete_rule
                    FROM information_schema.table_constraints AS tc
                    JOIN information_schema.key_column_usage AS kcu
                        ON tc.constraint_name = kcu.constraint_name
                    JOIN information_schema.constraint_column_usage AS ccu
                        ON ccu.constraint_name = tc.constraint_name
                    JOIN information_schema.referential_constraints AS rc
                        ON rc.constraint_name = tc.constraint_name
                    WHERE tc.table_name = %s
                    AND tc.constraint_type = 'FOREIGN KEY';
                """, (table_name,))
                fks = cursor.fetchall()
                
                # Índices
                cursor.execute("""
                    SELECT
                        indexname,
                        indexdef
                    FROM pg_indexes
                    WHERE tablename = %s
                    AND schemaname = 'public';
                """, (table_name,))
                indexes = cursor.fetchall()
                
                # Triggers
                cursor.execute("""
                    SELECT
                        trigger_name,
                        event_manipulation,
                        action_timing,
                        action_statement
                    FROM information_schema.triggers
                    WHERE event_object_table = %s
                    AND trigger_schema = 'public';
                """, (table_name,))
                triggers = cursor.fetchall()
                
                # Check constraints
                cursor.execute("""
                    SELECT
                        constraint_name,
                        check_clause
                    FROM information_schema.check_constraints
                    WHERE constraint_schema = 'public'
                    AND constraint_name IN (
                        SELECT constraint_name
                        FROM information_schema.constraint_table_usage
                        WHERE table_name = %s
                    );
                """, (table_name,))
                checks = cursor.fetchall()
                
                # Estadísticas de la tabla
                cursor.execute(f"""
                    SELECT 
                        COUNT(*) as row_count,
                        pg_size_pretty(pg_total_relation_size('{table_name}')) as total_size
                    FROM {table_name};
                """)
                stats = cursor.fetchone()
                
                self.schema['tables'][table_name] = {
                    'type': table['table_type'],
                    'columns': [dict(col) for col in columns],
                    'primary_key': [dict(p) for p in pk],
                    'foreign_keys': [dict(fk) for fk in fks],
                    'indexes': [dict(idx) for idx in indexes],
                    'triggers': [dict(trg) for trg in triggers],
                    'check_constraints': [dict(chk) for chk in checks],
                    'statistics': dict(stats) if stats else {}
                }
    
    def extract_views(self):
        """Extrae información de todas las vistas"""
        print("\n👁️ Extrayendo vistas...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    table_name as view_name,
                    view_definition
                FROM information_schema.views
                WHERE table_schema = 'public'
                ORDER BY table_name;
            """)
            views = cursor.fetchall()
            
            for view in views:
                view_name = view['view_name']
                print(f"   👁️ Vista: {view_name}")
                
                self.schema['views'][view_name] = {
                    'definition': view['view_definition']
                }
    
    def extract_functions(self):
        """Extrae todas las funciones y procedimientos almacenados"""
        print("\n⚙️ Extrayendo funciones...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    p.proname as function_name,
                    pg_get_function_arguments(p.oid) as arguments,
                    pg_get_function_result(p.oid) as return_type,
                    l.lanname as language,
                    p.prosrc as source_code,
                    obj_description(p.oid) as description
                FROM pg_proc p
                JOIN pg_namespace n ON p.pronamespace = n.oid
                JOIN pg_language l ON p.prolang = l.oid
                WHERE n.nspname = 'public'
                ORDER BY p.proname;
            """)
            functions = cursor.fetchall()
            
            for func in functions:
                func_name = func['function_name']
                print(f"   ⚙️ Función: {func_name}")
                
                self.schema['functions'][func_name] = dict(func)
    
    def extract_sequences(self):
        """Extrae información de las secuencias"""
        print("\n🔢 Extrayendo secuencias...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    sequence_name,
                    data_type,
                    start_value,
                    minimum_value,
                    maximum_value,
                    increment
                FROM information_schema.sequences
                WHERE sequence_schema = 'public'
                ORDER BY sequence_name;
            """)
            sequences = cursor.fetchall()
            
            for seq in sequences:
                seq_name = seq['sequence_name']
                print(f"   🔢 Secuencia: {seq_name}")
                
                self.schema['sequences'][seq_name] = dict(seq)
    
    def extract_relationships(self):
        """Extrae y mapea todas las relaciones entre tablas"""
        print("\n🔗 Mapeando relaciones...")
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT
                    tc.table_name as from_table,
                    kcu.column_name as from_column,
                    ccu.table_name as to_table,
                    ccu.column_name as to_column,
                    tc.constraint_name,
                    rc.update_rule,
                    rc.delete_rule
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu
                    ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage AS ccu
                    ON ccu.constraint_name = tc.constraint_name
                JOIN information_schema.referential_constraints AS rc
                    ON rc.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_schema = 'public'
                ORDER BY tc.table_name, kcu.column_name;
            """)
            relationships = cursor.fetchall()
            
            for rel in relationships:
                print(f"   🔗 {rel['from_table']}.{rel['from_column']} → {rel['to_table']}.{rel['to_column']}")
                self.schema['relationships'].append(dict(rel))
    
    def generate_erd_mermaid(self):
        """Genera diagrama ER en formato Mermaid"""
        print("\n📊 Generando diagrama ER (Mermaid)...")
        
        mermaid = ["erDiagram"]
        
        # Agregar relaciones
        for rel in self.schema['relationships']:
            from_table = rel['from_table']
            to_table = rel['to_table']
            constraint = rel['constraint_name']
            
            # Determinar cardinalidad (simplificado)
            cardinality = "||--o{"  # Uno a muchos por defecto
            
            mermaid.append(f"    {from_table} {cardinality} {to_table} : \"{constraint}\"")
        
        # Agregar atributos de tablas
        for table_name, table_info in self.schema['tables'].items():
            mermaid.append(f"    {table_name} {{")
            
            for col in table_info['columns']:
                col_name = col['column_name']
                col_type = col['data_type']
                nullable = "NULL" if col['is_nullable'] == 'YES' else "NOT NULL"
                
                # Marcar PKs
                is_pk = any(pk['attname'] == col_name for pk in table_info['primary_key'])
                pk_marker = "PK" if is_pk else ""
                
                mermaid.append(f"        {col_type} {col_name} {pk_marker} {nullable}")
            
            mermaid.append("    }")
        
        return "\n".join(mermaid)
    
    def generate_markdown_documentation(self):
        """Genera documentación completa en Markdown"""
        print("\n📝 Generando documentación Markdown...")
        
        md = [f"# 🗄️ Documentación de Base de Datos: {self.connection_params['database']}\n"]
        md.append(f"**Fecha de extracción:** {self.schema['metadata']['extraction_date']}\n")
        md.append(f"**PostgreSQL:** {self.schema['metadata']['postgresql_version']}\n")
        
        # Resumen
        md.append("## 📊 Resumen\n")
        counts = self.schema['metadata']['object_counts']
        md.append(f"- **Tablas:** {counts['total_tables']}")
        md.append(f"- **Vistas:** {counts['total_views']}")
        md.append(f"- **Funciones:** {counts['total_functions']}")
        md.append(f"- **Triggers:** {counts['total_triggers']}")
        md.append(f"- **Índices:** {counts['total_indexes']}\n")
        
        # Tablas
        md.append("## 📋 Tablas\n")
        for table_name, table_info in self.schema['tables'].items():
            md.append(f"### 🗂️ {table_name}\n")
            
            stats = table_info.get('statistics', {})
            md.append(f"**Registros:** {stats.get('row_count', 'N/A')}  ")
            md.append(f"**Tamaño:** {stats.get('total_size', 'N/A')}\n")
            
            # Columnas
            md.append("#### Columnas\n")
            md.append("| Columna | Tipo | Nulable | Default | Descripción |")
            md.append("|---------|------|---------|---------|-------------|")
            
            for col in table_info['columns']:
                col_name = col['column_name']
                data_type = col['data_type']
                nullable = "✅" if col['is_nullable'] == 'YES' else "❌"
                default = col['column_default'] or "-"
                
                # Marcar PKs y FKs
                is_pk = any(pk['attname'] == col_name for pk in table_info['primary_key'])
                is_fk = any(fk['column_name'] == col_name for fk in table_info['foreign_keys'])
                
                markers = []
                if is_pk:
                    markers.append("🔑 PK")
                if is_fk:
                    markers.append("🔗 FK")
                
                description = " ".join(markers) if markers else "-"
                
                md.append(f"| {col_name} | {data_type} | {nullable} | {default} | {description} |")
            
            md.append("")
            
            # Foreign Keys
            if table_info['foreign_keys']:
                md.append("#### Relaciones (Foreign Keys)\n")
                for fk in table_info['foreign_keys']:
                    md.append(f"- `{fk['column_name']}` → `{fk['foreign_table_name']}.{fk['foreign_column_name']}`")
                    md.append(f"  - ON UPDATE: {fk['update_rule']}")
                    md.append(f"  - ON DELETE: {fk['delete_rule']}")
                md.append("")
            
            # Índices
            if table_info['indexes']:
                md.append("#### Índices\n")
                for idx in table_info['indexes']:
                    md.append(f"- `{idx['indexname']}`")
                md.append("")
            
            md.append("---\n")
        
        # Vistas
        if self.schema['views']:
            md.append("## 👁️ Vistas\n")
            for view_name, view_info in self.schema['views'].items():
                md.append(f"### {view_name}\n")
                md.append("```sql")
                md.append(view_info['definition'])
                md.append("```\n")
        
        # Funciones
        if self.schema['functions']:
            md.append("## ⚙️ Funciones\n")
            for func_name, func_info in self.schema['functions'].items():
                md.append(f"### {func_name}\n")
                md.append(f"**Argumentos:** `{func_info['arguments']}`  ")
                md.append(f"**Retorna:** `{func_info['return_type']}`  ")
                md.append(f"**Lenguaje:** {func_info['language']}\n")
                md.append("```sql")
                md.append(func_info['source_code'])
                md.append("```\n")
        
        # Diagrama ER
        md.append("## 📊 Diagrama de Entidad-Relación\n")
        md.append("```mermaid")
        md.append(self.generate_erd_mermaid())
        md.append("```\n")
        
        return "\n".join(md)
    
    def save_documentation(self, output_dir="database_docs"):
        """Guarda la documentación en archivos"""
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Guardar JSON completo
        json_path = os.path.join(output_dir, "schema_complete.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.schema, f, indent=2, ensure_ascii=False, default=str)
        print(f"✅ Schema JSON guardado: {json_path}")
        
        # Guardar Markdown
        md_path = os.path.join(output_dir, "database_documentation.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_markdown_documentation())
        print(f"✅ Documentación Markdown guardada: {md_path}")
        
        # Guardar diagrama Mermaid
        mermaid_path = os.path.join(output_dir, "erd_diagram.mmd")
        with open(mermaid_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_erd_mermaid())
        print(f"✅ Diagrama Mermaid guardado: {mermaid_path}")
    
    def extract_all(self):
        """Ejecuta toda la extracción"""
        print("\n🚀 Iniciando extracción completa de esquema...\n")
        
        if not self.connect():
            return False
        
        try:
            self.extract_metadata()
            self.extract_tables()
            self.extract_views()
            self.extract_functions()
            self.extract_sequences()
            self.extract_relationships()
            
            print("\n✅ Extracción completada exitosamente")
            return True
            
        except Exception as e:
            print(f"\n❌ Error durante la extracción: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            self.disconnect()


def main():
    """Función principal"""
    # 🔧 CONFIGURACIÓN - Ajusta según tu base de datos
    extractor = DatabaseSchemaExtractor(
        host="192.168.18.92",
        database="db_tesis",
        user="postgres",
        password="1234",
        port="5432"
    )
    
    # Extraer esquema completo
    if extractor.extract_all():
        # Guardar documentación
        extractor.save_documentation("database_docs")
        
        print("\n" + "="*60)
        print("📚 DOCUMENTACIÓN GENERADA:")
        print("="*60)
        print("1. schema_complete.json - Esquema completo en JSON")
        print("2. database_documentation.md - Documentación en Markdown")
        print("3. erd_diagram.mmd - Diagrama ER en Mermaid")
        print("="*60)


if __name__ == "__main__":
    main()