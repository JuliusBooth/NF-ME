package main

import (
	"bufio"
	"fmt"
	"os"

	ch "NF-Me/pkg/cryptography"
	io "NF-Me/pkg/file"

	"github.com/akamensky/argparse"
)

func createPublicKey(fileName *string) {
	publicKey, _ := ch.CreateKeys()
	io.SavePublicKey(publicKey, *fileName)
}

func sign(fileName *string) {
	privateKey := ch.GetPrivateKey()
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter message to sign: ")
	message, _ := reader.ReadString('\n')
	signature := ch.SignMessageWithKey(privateKey, message)
	io.SaveSignature(signature, *fileName)
}

func verify(publicKeyFile *string, signatureFile *string) {
	publicKey := io.GetPublicKeyFromFile(publicKeyFile)
	message := io.GetMessageToVerify()
	signature := io.GetSignatureFromFile(signatureFile)
	if ch.VerifyMessageFromKey(publicKey, message, signature) {
		fmt.Println("Message is verified")
	} else {
		fmt.Println("Message is not verified")
	}
}

func main() {
	parser := argparse.NewParser("nf-me", "A program that creates a public key, signs a message, and verifies a message")
	createKey := parser.Flag("c", "create public key", &argparse.Options{Required: false})
	signMessage := parser.Flag("s", "sign message", &argparse.Options{Required: false})
	verifyMessage := parser.Flag("v", "verify message", &argparse.Options{Required: false})
	publicKeyFileName := parser.String("p", "public key file name", &argparse.Options{Required: false, Default: "publickey.pem"})
	signatureFileName := parser.String("f", "signature file name", &argparse.Options{Required: false, Default: "signature.txt"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	if *createKey {
		createPublicKey(publicKeyFileName)
	}

	if *signMessage {
		sign(signatureFileName)
	}

	if *verifyMessage {
		verify(publicKeyFileName, signatureFileName)
	}
}

