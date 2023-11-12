package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
)

func mod(base, exp, mod *big.Int) *big.Int {
	result := new(big.Int).SetInt64(1)
	zero := new(big.Int)

	base = new(big.Int).Mod(base, mod)

	for exp.Cmp(zero) > 0 {
		if exp.Bit(0) == 1 {
			result = new(big.Int).Mod(new(big.Int).Mul(result, base), mod)
		}
		exp = new(big.Int).Rsh(exp, 1)
		base = new(big.Int).Mod(new(big.Int).Mul(base, base), mod)
	}

	return result
}

func main() {

	conn, err := net.Dial("tcp", "127.0.0.1:65001")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	for {
		// Solicitar al usuario que ingrese un mensaje
		var mensaje string
		fmt.Print("Ingrese un mensaje (o 'exit' para salir): ")
		fmt.Scanln(&mensaje)

		if mensaje == "exit" {
			break
		}

		// Cifrar el mensaje con DES usando la clave compartida
		mensajeCifrado, err := encryptDES([]byte(mensaje), sharedKey.Bytes()[:8])
		if err != nil {
			fmt.Println("Error cifrando el mensaje:", err)
			return
		}

		// Enviar mensaje cifrado al servidor
		conn.Write(mensajeCifrado)
		fmt.Println("Mensaje cifrado y enviado:", mensaje)
	}
}

// encryptDES realiza el cifrado utilizando el modo CBC
func encryptDES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Añadir relleno al texto plano
	plaintext = pad(plaintext, block.BlockSize())

	// Generar un IV (Initialization Vector) aleatorio
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Crear un cifrador CBC con el bloque y el IV
	mode := cipher.NewCBCEncrypter(block, iv)

	// Cifrar el texto plano
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Concatenar el IV cifrado con el texto cifrado
	result := append(iv, ciphertext...)
	return result, nil
}

func decryptDES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extraer el IV del comienzo del texto cifrado
	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	// Crear un descifrador CBC con el bloque y el IV
	mode := cipher.NewCBCDecrypter(block, iv)

	// Descifrar el texto cifrado
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Quitar el relleno del texto plano
	plaintext, err = unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// pad añade relleno al texto plano
func pad(input []byte, blockSize int) []byte {
	padding := blockSize - (len(input) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(input, padText...)
}

// unpad elimina el relleno del texto plano
func unpad(input []byte) ([]byte, error) {
	length := len(input)
	unpadding := int(input[length-1])

	if unpadding > length {
		return nil, errors.New("Texto plano mal formado")
	}

	return input[:(length - unpadding)], nil
}
