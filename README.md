# Cliente-Servidor Diffie-Hellman con DES

Se implementación un sistema cliente-servidor que utiliza el intercambio de claves Diffie-Hellman para establecer una clave compartida y cifra/descifra mensajes usando el algoritmo de cifrado DES.

![Deffi Hellman](./img/diffie-hellman.png)

## Estructura 

- **server.py**: Implementa el servidor en Python.
- **client.go**: Implementa el cliente en Python.
- **mensajerecibido.txt**: Archivo donde se guarda el mensaje descifrado.

### Instrucciones de Uso

1. **Clonar el Repositorio:**

2. **Instalar Dependencias Python:**
    - Asegúrate de tener instalado `python`
    ```bash
        pip install -r requirements.txt
    ```

3. **Ejecutar el Servidor:**
    ```bash
    python3 server.py
    ```

4. **Ejecutar el Cliente:**
    - Asegúrate de tener Go instalado.
    ```bash
    go run client.go
    ```

5. **Verificar Resultados:**
    - El mensaje descifrado se guardará en el archivo `mensajerecibido.txt`.

### Notas Importantes

- Asegúrate de tener Python3 instalado.
- La comunicación entre el cliente y el servidor se realiza a través del puerto 65000, se puede cambiar en el código.
- Se utiliza Diffie-Hellman para el intercambio de claves y DES para el cifrado de mensajes.

### Requisitos del Sistema

- Python 3.x
- Pipenv (opcional)

### Integrantes

- Sebastian Allende
- Gianfranco Astorga
