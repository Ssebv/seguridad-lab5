from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
import os

def recibir_mensaje_cifrado(conn, key, carpeta):
    
    iv = conn.recv(8)  # Recibir el IV del cliente para poder descifrar el mensaje
    mensaje_cifrado = conn.recv(1024) # Recibir el mensaje cifrado del cliente

    # print(f"Tamaño del IV recibido: {len(iv)} bytes")
    # print(f"Tamaño del mensaje cifrado recibido: {len(mensaje_cifrado)} bytes")

    if not mensaje_cifrado: # Mensaje vacio significa que el cliente se desconecto
        return None
    
    cipher = DES.new(key, DES.MODE_CBC, IV=iv)
    mensaje_descifrado = unpad(cipher.decrypt(mensaje_cifrado), DES.block_size)
    
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)
        
    archivo = os.path.join(carpeta, 'mensajeRecibido.txt') # Se crea el archivo donde se guardara el mensaje recibido

        
    with open(archivo, 'a') as file:
        file.write(mensaje_descifrado.decode() + '\n') # Se escribe el mensaje recibido en el archivo
        
    return mensaje_descifrado # Retornar mensaje descifrado

def enviar_mensaje_cifrado(conn, mensaje, key): # Aqui se cifra el mensaje y se envia
    
    iv = get_random_bytes(8) # Generar IV aleatorio, que es de 8 bytes para DES porque es un cifrado de bloque y el tamaño del bloque es de 64 bits (8 bytes)
    # print("IV:", iv)
    cipher = DES.new(key, DES.MODE_CBC, IV=iv) # Se crea el objeto cipher con la clave compartida y el IV generado
    mensaje_cifrado = cipher.encrypt(pad(mensaje.encode(), DES.block_size)) # Se cifra el mensaje con el metodo encrypt y se le agrega padding para que el mensaje tenga un tamaño multiplo del tamaño del bloque

   #  print(f"Tamaño del IV enviado: {len(iv)} bytes")
   #  print(f"Tamaño del mensaje cifrado: {len(mensaje_cifrado)} bytes")

    conn.sendall(iv + mensaje_cifrado) # Enviar IV + mensaje cifrado

def mod(base, exp, mod): # Funcion que calcula el modulo 
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result