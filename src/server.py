import random
import socket

from crypto_utils import *

def generador_claves(p, g):
    private_key = random.randint(1, p - 1)
    public_key = mod(g, private_key, p)
    return private_key, public_key

def recibir_clave_publica(conn):
    public_key_bytes = conn.recv(1024)
    public_key = int.from_bytes(public_key_bytes, 'big')
    return public_key

def enviar_clave_publica(conn, key):
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    conn.sendall(key_bytes)
    
def intercambio_diffie_hellman(conn, p, g):
    private_key, public_key = generador_claves(p, g)
    enviar_clave_publica(conn, public_key)
    client_public_key = recibir_clave_publica(conn)
    shared_key = mod(client_public_key, private_key, p).to_bytes(8, 'big')
    print('Clave compartida:', shared_key)
    return shared_key

def main():

    host = '127.0.0.1'
    port = 65000
    p = 23  # Puede cambiar estos valores por valores reales de p y g utilizados en su implementación
    g = 5
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f'Esperando conexión en {host}:{port}')
        conn, addr = s.accept()
        
        try:
            with conn:
                print('Conectado a', addr)

                # Realizar intercambio Diffie-Hellman
                shared_key = intercambio_diffie_hellman(conn, p, g)
                
                while True:
                    mensaje_descifrado = recibir_mensaje_cifrado(conn, shared_key, 'mensajesRecibidos.txt')
                    if mensaje_descifrado is None:
                        break
                    elif mensaje_descifrado is not None:
                        print("Mensaje recibido:", mensaje_descifrado.decode())

        except Exception as e:
            print(f"Error: {e}")
            
if __name__ == '__main__':
    main()