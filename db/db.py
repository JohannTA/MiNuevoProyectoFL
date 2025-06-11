import psycopg2
from psycopg2.extras import RealDictCursor

#postgresql://postgres:SkpzaNfrqZsvqqIpCvJmktLsvdUotNPt@gondola.proxy.rlwy.net:24833/railway
def obtener_conexion():
    """Obtiene una conexión a la base de datos PostgreSQL."""
    try:
        # Configura aquí tus credenciales de base de datos
        conn = psycopg2.connect(
            host="pg-22d24983-johannaguinaga20-3d3c.j.aivencloud.com",
            database="db_tesis",
            user="avnadmin",
            password="AVNS_I1jdawtNztL0mWzlO5_",
            port="11410"
        )
        return conn
    except psycopg2.Error as e:
        print(f"Error al conectar a PostgreSQL: {e}")
        return None

def probar_conexion():
    """Prueba la conexión a la base de datos."""
    conn = obtener_conexion()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                version = cur.fetchone()[0]
                print(f"Conexión exitosa a PostgreSQL. Versión: {version}")
                return True
        except psycopg2.Error as e:
            print(f"Error al probar la conexión: {e}")
            return False
        finally:
            conn.close()
    return False

# Si se ejecuta este archivo directamente, probar la conexión
if __name__ == "__main__":
    exito = probar_conexion()
    print(f"Prueba de conexión: {'Exitosa' if exito else 'Fallida'}")