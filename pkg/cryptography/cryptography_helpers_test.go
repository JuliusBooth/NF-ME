package cryptography

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestCreateKeysFromPassword(t *testing.T) {
	publicKey, privateKey := createKeysFromPassword("password")

	if publicKey.Curve != elliptic.P256() {
		t.Error("Expected elliptic curve to be P256")
	}
	if privateKey.PublicKey.Curve != elliptic.P256() {
		t.Error("Expected elliptic curve to be P256")
	}
	if privateKey.D == nil {
		t.Error("Expected private key D to not be nil")
	}

	expectedPublicKeyXBytes := []byte{194, 116, 128, 18, 142, 233, 141, 172, 199, 100, 193, 223, 227, 140, 212, 3, 239, 42, 102, 56, 44, 130, 17, 55, 73, 71, 207, 124, 156, 97, 199, 15}

	if publicKey.X.Cmp(new(big.Int).SetBytes(expectedPublicKeyXBytes)) != 0 {
		t.Errorf("Expected publicKey.X to be %s", expectedPublicKeyXBytes)
	}
	if publicKey.X == nil {
		t.Error("Expected public key X to not be nil")
	}
	if publicKey.Y == nil {
		t.Error("Expected public key Y to not be nil")
	}
}

func TestVerifyMessageFromKey(t *testing.T) {
	publicKey, privateKey := createKeysFromPassword("password")
	message := "message"
	signature := SignMessageWithKey(privateKey, message)

	if !VerifyMessageFromKey(publicKey, message, signature) {
		t.Error("Expected message to be verified")
	}

	wrongPublicKey, _ := createKeysFromPassword("wrong password")
	if VerifyMessageFromKey(wrongPublicKey, message, signature) {
		t.Error("Expected message to not be verified")
	}

	if VerifyMessageFromKey(publicKey, "wrong message", signature) {
		t.Error("Expected message to not be verified")
	}

	wrongSignature := SignMessageWithKey(privateKey, "wrong message")
	if VerifyMessageFromKey(publicKey, message, wrongSignature) {
		t.Error("Expected message to not be verified")
	}
}

