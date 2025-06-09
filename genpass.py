import hashlib
import sys

def generar_hash_sha256(texto):
    """Genera un hash SHA256 a partir de un texto"""
    # Convertir el texto a bytes
    texto_bytes = texto.encode('utf-8')
    
    # Generar el hash
    hash_obj = hashlib.sha256(texto_bytes)
    
    # Obtener el hash en formato hexadecimal
    hash_hex = hash_obj.hexdigest()
    
    return hash_hex

if __name__ == "__main__":
    # Verificar si se proporcionó una contraseña como argumento
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        # Si no se proporcionó, pedirla al usuario
        password = input("Ingrese la contraseña a convertir: ")
    
    # Generar el hash
    hash_result = generar_hash_sha256(password)
    
    # Mostrar el resultado
    print("\n==== Resultado ====")
    print(f"Contraseña original: {password}")
    print(f"Hash SHA256: {hash_result}")
    print("\n==== SQL para insertar en la base de datos ====")
    print(f"-- Para usuario 'admin':")
    print(f"INSERT INTO users (username, email, password_hash, first_name, last_name, role_id, is_active)")
    print(f"VALUES ('admin', 'admin@example.com', '{hash_result}', 'Administrador', 'Sistema', 1, true);")
    print("\n-- Nota: Asegúrate de que el role_id=1 corresponda al rol de administrador en tu base de datos")