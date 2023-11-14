import random
import socket

from crypto_utils import *

def generador_claves(p, g): # Generador de claves Diffie-Hellman
    private_key = random.randint(1, p - 1) # Generar clave privada
    public_key = mod(g, private_key, p) # Generar clave publica
    return private_key, public_key

def recibir_clave_publica(conn): # Funcion que recibe la clave publica del cliente
    public_key_bytes = conn.recv(1024) 
    public_key = int.from_bytes(public_key_bytes, 'big') # Convertir clave publica a entero por medio de bytes
    return public_key

def enviar_clave_publica(conn, key): # Funcion que envia la clave publica al cliente
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big') # Convertir clave publica a bytes
    conn.sendall(key_bytes) # Enviar clave publica al cliente
    
def intercambio_diffie_hellman(conn, p, g): # Funcion que realiza el intercambio Diffie-Hellman de claves
    
    private_key, public_key = generador_claves(p, g) # Generar claves
    enviar_clave_publica(conn, public_key) # Enviar clave publica al cliente
    client_public_key = recibir_clave_publica(conn) # Recibir clave publica del cliente
    shared_key = mod(client_public_key, private_key, p).to_bytes(8, 'big') # Generar clave compartida
    print('Clave compartida:', shared_key) # Imprimir clave compartida
    return shared_key

def main():

    host = '127.0.0.1'
    port = 65000
    
    # Parametros Diffie-Hellman, se utilizaran valores pequeños para que el programa sea mas rapido y explicativo
    p = 23 
    g = 5 # Generador
    
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
                    mensaje_descifrado = recibir_mensaje_cifrado(conn, shared_key, 'mensaje') 
                    if mensaje_descifrado is None:
                        break
                    elif mensaje_descifrado is not None:
                        print("Mensaje recibido:", mensaje_descifrado.decode())

        except Exception as e:
            print(f"Error: {e}")
            
if __name__ == '__main__':
    main()