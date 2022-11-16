package cryptography

import (
	"NF-Me/pkg/file"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func getPrivateKeyFromPassword(password string) ecdsa.PrivateKey {
	hash := sha256.Sum256([]byte(password))
	privateKey := ecdsa.PrivateKey{}
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.D = new(big.Int).SetBytes(hash[:])
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(hash[:])
	return privateKey
}

func GetPrivateKey() ecdsa.PrivateKey {
	password := file.GetPasswordInput()
	return getPrivateKeyFromPassword(password)
}
	
func createKeysFromPassword(password string) (publicKey ecdsa.PublicKey, privateKey ecdsa.PrivateKey){
	privateKey = getPrivateKeyFromPassword(password)
	publicKey = privateKey.PublicKey
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
	return signature
}

func VerifyMessageFromKey(publicKey ecdsa.PublicKey, message string, signature []byte) bool {
	r := big.Int{}
	r.SetBytes(signature[:len(signature)/2])
	s := big.Int{}
	s.SetBytes(signature[len(signature)/2:])
	return ecdsa.Verify(&publicKey, []byte(message), &r, &s)
}