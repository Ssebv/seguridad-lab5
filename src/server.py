import random
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def mod(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Función para generar claves deffie-hellman
def generador_claves(p, g): # p y g son los parámetros públicos
    private_key = random.randint(1, p - 1)
    public_key = mod(g, private_key, p)
    return private_key, public_key

# Reciviir clave pública 
def recibir_clave_publica(conn):
    # Recibir clave pública
    public_key = int(conn.recv(1024).decode())
    return public_key

# Enviar clave publica
def enviar_clave_publica(conn, key):
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
    conn.send(key_bytes)

def cifrar_mensaje(mensaje, key):
    cipher = DES.new(str(key).encode(), DES.MODE_ECB)
    mensaje_cifrado = cipher.encrypt(pad(mensaje.encode(), 8))
    return mensaje_cifrado

def descifrar_mensaje(mensaje_cifrado, key):
    cipher = DES.new(str(key).encode(), DES.MODE_ECB)
    mensaje_descifrado = unpad(cipher.decrypt(mensaje_cifrado), 8).decode()
    return mensaje_descifrado 

def main():
    host = '127.0.0.1'
    port = 65002
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f'Esperando conexión en {host}:{port}')
        conn, addr = s.accept()
        
        try:
            with conn:
                print('Conectado a', addr)
                
                # Recibir parámetros públicos Diffie-Hellman
                p = int(conn.recv(1024).decode())
                g = int(conn.recv(1024).decode())
                
                # Generar claves Diffie-Hellman
                private_key, public_key = generador_claves(p, g)
                
                # Enviar clave pública al cliente
                enviar_clave_publica(conn, public_key)
                
                # Recibir clave pública del cliente
                client_public_key = recibir_clave_publica(conn)
                
                # Calcular clave compartida
                shared_key = mod(client_public_key, private_key, p)
                print('Clave compartida:', shared_key)
                
                # Recibir mensaje cifrado del cliente
                mensaje_cifrado = conn.recv(1024)
                print('Mensaje cifrado recibido:', mensaje_cifrado)
                
                # Descifrar el mensaje con DES
                mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, shared_key)
                print('Mensaje descifrado:', mensaje_descifrado)
                
                # Escribir el mensaje descifrado en un archivo
                with open('mensajerecibido.txt', 'w') as file:
                    file.write(mensaje_descifrado)
                    print('Mensaje descifrado escrito en mensajerecibido.txt')
                
                conn.close()
                print('Conexión cerrada')
        
        except Exception as e:
            print(f"Error: {e}")
            
if __name__ == '__main__':
    main()