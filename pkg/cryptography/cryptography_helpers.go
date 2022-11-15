package cryptography

import (
	"NF-Me/pkg/file"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func getPrivateKeyFromPassword(password string) ecdsa.PrivateKey {
	hash := sha256.Sum256([]byte(password))
	fmt.Println("hash: ", hash)

	privateKey := ecdsa.PrivateKey{}
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.D = new(big.Int).SetBytes(hash[:])
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(hash[:])
	fmt.Println("privateKey: ", privateKey)
	return privateKey
}

func GetPrivateKey() ecdsa.PrivateKey {
	password := file.GetPasswordInput()
	return getPrivateKeyFromPassword(password)
}

func SavePublicKey(publicKey ecdsa.PublicKey) {
	fileName := file.ReadFileName()

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&publicKey)
	fmt.Println("publicKeyBytes: ", publicKeyBytes)

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	fmt.Println("block: ", block)
	pem.Encode(file, block)
}
	
func createKeysFromPassword(password string) (publicKey ecdsa.PublicKey, privateKey ecdsa.PrivateKey){
	privateKey = getPrivateKeyFromPassword(password)
	publicKey = privateKey.PublicKey
	fmt.Println("publicKey: ", publicKey)
	return publicKey, privateKey
}

func CreateKeys() (publicKey ecdsa.PublicKey, privateKey ecdsa.PrivateKey) {
	password := file.GetPasswordInput()
	return createKeysFromPassword(password)
}

func SignMessageWithKey(privateKey ecdsa.PrivateKey, message string) []byte {
	r, s, _ := ecdsa.Sign(rand.Reader, &privateKey, []byte(message))
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	signature := append(rBytes, sBytes...)
	fmt.Println("signature: ", signature)
	return signature
}

func VerifyMessageFromKey(publicKey ecdsa.PublicKey, message string, signature []byte) bool {
	r := big.Int{}
	r.SetBytes(signature[:len(signature)/2])
	s := big.Int{}
	s.SetBytes(signature[len(signature)/2:])
	return ecdsa.Verify(&publicKey, []byte(message), &r, &s)
}