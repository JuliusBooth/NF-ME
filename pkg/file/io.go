package file

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/term"
)

func ReadFileName() string {
	fmt.Print("Enter file name: ")
	reader := bufio.NewReader(os.Stdin)
	fileName, _ := reader.ReadString('\n')
	fileName = fileName[:len(fileName)-1]

	fmt.Println("fileName: ", fileName)
	return fileName
}

func GetPasswordInput() string {
	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(0)
	fmt.Println()
	return string(password)
}

func SaveSignature(signature []byte, fileName string) {
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	file.Write(signature)
}

func GetSignatureFromFile(fileName *string) []byte {
	file, err := os.Open(*fileName)
	if err != nil {
		fmt.Println(err)
		return []byte{}
	}
	defer file.Close()

	info, _ := file.Stat()
	size := info.Size()
	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pemBytes)
	if err != nil{
		fmt.Println(err)
		return []byte{}
	}
	return pemBytes
}

func GetPublicKeyFromFile(fileName *string) ecdsa.PublicKey {
	file, err := os.Open(*fileName)
	if err != nil {
		fmt.Println(err)
		return ecdsa.PublicKey{}
	}
	defer file.Close()
	info, _ := file.Stat()
	size := info.Size()
	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		fmt.Println(err)
		return ecdsa.PublicKey{}
	}
	data, _ := pem.Decode([]byte(pemBytes))
	publicKey, _ := x509.ParsePKIXPublicKey(data.Bytes)
	return *publicKey.(*ecdsa.PublicKey)
}

func SavePublicKey(publicKey ecdsa.PublicKey, fileName string) {
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&publicKey)
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pem.Encode(file, block)
}

func GetMessageToVerify() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter message to verify: ")
	message, _ := reader.ReadString('\n')
	return message
}