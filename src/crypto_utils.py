from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
import os

def recibir_mensaje_cifrado(conn, key, carpeta):
    iv = conn.recv(8)  # Recibir el IV del cliente
    mensaje_cifrado = conn.recv(1024)

    print(f"Tamaño del IV recibido: {len(iv)} bytes")
    print(f"Tamaño del mensaje cifrado recibido: {len(mensaje_cifrado)} bytes")

    if not mensaje_cifrado:
        return None
    cipher = DES.new(key, DES.MODE_CBC, IV=iv)
    mensaje_descifrado = unpad(cipher.decrypt(mensaje_cifrado), DES.block_size)
    
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)
        
    archivo = os.path.join(carpeta, 'mensajeRecibido.txt')

        
    with open(archivo, 'a') as file:
        file.write(mensaje_descifrado.decode() + '\n')
        
    return mensaje_descifrado

def enviar_mensaje_cifrado(conn, mensaje, key): # Aqui se cifra el mensaje y se envia
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, IV=iv)
    mensaje_cifrado = cipher.encrypt(pad(mensaje.encode(), DES.block_size))

    print(f"Tamaño del IV enviado: {len(iv)} bytes")
    print(f"Tamaño del mensaje cifrado: {len(mensaje_cifrado)} bytes")

    conn.sendall(iv + mensaje_cifrado) # Enviar IV + mensaje cifrado

def mod(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result