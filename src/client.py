import socket

from crypto_utils import *

def generador_claves(p, g): 
    private_key = get_random_bytes(8)
    public_key = mod(g, int.from_bytes(private_key, 'big'), p)
    return private_key, public_key

def enviar_clave_publica(conn, key): # Enviar clave publica al servidor
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    conn.sendall(key_bytes)

def recibir_clave_publica(conn): # Recibir clave publica del servidor
    public_key_bytes = conn.recv(1024)
    public_key = int.from_bytes(public_key_bytes, 'big')
    return public_key

def intercambio_diffie_hellman(conn, p, g): # Funcion que realiza el intercambio Diffie-Hellman de claves
    private_key, public_key = generador_claves(p, g)
    enviar_clave_publica(conn, public_key)
    server_public_key = recibir_clave_publica(conn)
    shared_key = mod(server_public_key, int.from_bytes(private_key, 'big'), p).to_bytes(8, 'big') # Generar clave compartida
    print('Clave compartida:', shared_key)
    return shared_key

def main():
    
    # Parametros de conexion
    host = "127.0.0.1"
    port = 65000
    
    # Parametros Diffie-Hellman
    p = 23 
    g = 5

    try:
        conn = socket.create_connection((host, port))
        conn.settimeout(5)

        print(f"Conectado a {host}:{port}")

        # Realizar intercambio Diffie-Hellman
        shared_key = intercambio_diffie_hellman(conn, p, g)

        while True:
            mensaje = input("Ingrese un mensaje (o 'exit' para salir): ")

            if mensaje == "exit":
                break
            
            # print("Tipo de mensaje:", type(mensaje))
            enviar_mensaje_cifrado(conn, mensaje, shared_key)
            print("Mensaje enviado")
    
    except socket.timeout:
        print("Tiempo de espera agotado. La conexión se cerrará.")

    except Exception as e:
        print("Error connecting:", e)
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()
