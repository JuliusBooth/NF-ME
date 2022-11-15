package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	ch "NF-Me/pkg/cryptography"
	io "NF-Me/pkg/file"

	"github.com/akamensky/argparse"
)

func main() {
	parser := argparse.NewParser("nf-me", "A program that creates a public key, signs a message, and verifies a message")
	createPublicKey := parser.Flag("c", "create public key", &argparse.Options{Required: false})
	signMessage := parser.Flag("s", "sign message", &argparse.Options{Required: false})
	verifyMessage := parser.Flag("v", "verify message", &argparse.Options{Required: false})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	if *createPublicKey {
		publicKey, _ := ch.CreateKeys()
		ch.SavePublicKey(publicKey)
	}

	if *signMessage {
		privateKey := ch.GetPrivateKey()
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter message to sign: ")
		message, _ := reader.ReadString('\n')
		signature := ch.SignMessageWithKey(privateKey, message)
		io.SaveSignature(signature)
	}

	if *verifyMessage {
		fmt.Println("Getting public key from file...")
		fileName := io.ReadFileName()
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		info, _ := file.Stat()
		size := info.Size()
		pemBytes := make([]byte, size)
		buffer := bufio.NewReader(file)
		_, err = buffer.Read(pemBytes)
		if err != nil {
			fmt.Println(err)
			return
		}
		data, _ := pem.Decode([]byte(pemBytes))
		publicKey, _ := x509.ParsePKIXPublicKey(data.Bytes)
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter message to verify: ")
		message, _ := reader.ReadString('\n')
		fmt.Println("Getting signature from file...")
		fileName = io.ReadFileName()
		file, err = os.Open(fileName)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		info, _ = file.Stat()
		size = info.Size()
		pemBytes = make([]byte, size)
		buffer = bufio.NewReader(file)
		_, err = buffer.Read(pemBytes)
		if err != nil{
			fmt.Println(err)
			return
		}
		publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

		if ch.VerifyMessageFromKey(*publicKeyECDSA, message, pemBytes) {
			fmt.Println("Message is verified")
		} else {
			fmt.Println("Message is not verified")
		}
	}
}

