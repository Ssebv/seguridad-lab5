package main

import (
	"crypto/dsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
)

func modExp(base, exp, mod *big.Int) *big.Int {
	result := new(big.Int).SetInt64(1)
	base = new(big.Int).Mod(base, mod)
	zero := new(big.Int)

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
	conn, err := net.Dial("tcp", "127.0.0.1:65002")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to server")

	// Recibir parámetros públicos
	bufferP := make([]byte, 1024)
	n, err := conn.Read(bufferP)
	if err != nil {
		fmt.Println("Error receiving P:", err)
		return
	}

	p := new(big.Int).SetBytes(bufferP)
	fmt.Println("Received P:", p)

	bufferG := make([]byte, 1024)
	n, err = conn.Read(bufferG)
	if err != nil {
		fmt.Println("Error receiving G:", err)
		return
	}
	g := new(big.Int).SetBytes(bufferG)
	fmt.Println("Received G:", g)

	// Generar claves
	privateKey := new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = dsa.Parameters{
		P: p,
		Q: new(big.Int).SetInt64(2),
		G: g,
	}
	err = dsa.GenerateKey(privateKey, rand.Reader)
	if err != nil {
		fmt.Println("Error generating DSA keys:", err)
		return
	}

	// Enviar clave pública
	fmt.Println("Sending public key:", privateKey.PublicKey.Y)
	conn.Write(privateKey.PublicKey.Y.Bytes())

	// Recibir clave pública
	serverPublicKeyBytes := make([]byte, 2048)
	n, err = conn.Read(serverPublicKeyBytes)
	if err != nil {
		fmt.Println("Error receiving server's public key:", err)
		return
	}
	serverPublicKey := new(big.Int).SetBytes(serverPublicKeyBytes)
	fmt.Println("Received server's public key:", serverPublicKey)

	// Calcular clave compartida
	sharedKey := modExp(serverPublicKey, privateKey.X, p)
	fmt.Println("Shared Key:", sharedKey)

	// Enviar mensaje
	mensaje := "Hola, servidor!"
	conn.Write([]byte(mensaje))
	fmt.Println("Mensaje enviado al servidor:", mensaje)

	// Recibir mensaje
	buffer := make([]byte, 1024)
	n, err = conn.Read(buffer)

	if err != nil {
		fmt.Println("Error receiving message:", err)
		return
	}
	fmt.Println("Mensaje recibido del servidor:", string(buffer[:n]))
}
