import random
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

def mod(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def generador_claves(p, g):
    private_key = random.randint(1, p - 1)
    public_key = mod(g, private_key, p)
    return private_key, public_key

def recibir_clave_publica(conn):
    # Recibir clave pública
    public_key_bytes = conn.recv(1024)
    public_key = int.from_bytes(public_key_bytes, 'big')
    return public_key

def enviar_clave_publica(conn, key):
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    conn.sendall(key_bytes)
    
def recibir_mensaje_cifrado(conn, key):
    iv = conn.recv(8)  # Recibir el IV del cliente
    mensaje_cifrado = conn.recv(1024)

    print(f"Tamaño del IV recibido: {len(iv)} bytes")
    print(f"Tamaño del mensaje cifrado recibido: {len(mensaje_cifrado)} bytes")

    if not mensaje_cifrado:
        return None
    cipher = DES.new(key, DES.MODE_CBC, IV=iv)
    mensaje_descifrado = unpad(cipher.decrypt(mensaje_cifrado), DES.block_size)
    return mensaje_descifrado

def intercambio_diffie_hellman(conn, p, g):
    private_key, public_key = generador_claves(p, g)
    enviar_clave_publica(conn, public_key)
    client_public_key = recibir_clave_publica(conn)
    shared_key = mod(client_public_key, private_key, p).to_bytes(8, 'big')
    print('Clave compartida:', shared_key)
    return shared_key

def main():

    host = '127.0.0.1'
    port = 65001
    p = 23  # Puede cambiar estos valores por valores reales de p y g utilizados en su implementación
    g = 5
    # key = b'my_secret_key'  # Clave de cifrado DES
    
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
                    mensaje_descifrado = recibir_mensaje_cifrado(conn, shared_key)
                    if mensaje_descifrado is None:
                        break
                    elif mensaje_descifrado is not None:
                        print("Mensaje recibido:", mensaje_descifrado.decode())


        except Exception as e:
            print(f"Error: {e}")

            
if __name__ == '__main__':
    main()