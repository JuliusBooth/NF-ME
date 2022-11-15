package cryptography

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestCreateKeysFromPassword(t *testing.T) {

	publicKey, privateKey := createKeysFromPassword("password")

	// compare public key elliptic curve with expected
	if publicKey.Curve != elliptic.P256() {
		t.Error("Expected elliptic curve to be P256")
	}
	// compare private key elliptic curve with expected
	if privateKey.PublicKey.Curve != elliptic.P256() {
		t.Error("Expected elliptic curve to be P256")
	}
	if privateKey.D == nil {
		t.Error("Expected private key D to not be nil")
	}

	expectedPublicKeyXBytes := []byte{194, 116, 128, 18, 142, 233, 141, 172, 199, 100, 193, 223, 227, 140, 212, 3, 239, 42, 102, 56, 44, 130, 17, 55, 73, 71, 207, 124, 156, 97, 199, 15}

	if publicKey.X.Cmp(new(big.Int).SetBytes(expectedPublicKeyXBytes)) != 0 {
		// use string formatting to print out the actual value of expectedPublicKeyXBytes
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
	// create public key
	publicKey, privateKey := createKeysFromPassword("password")
	// create message
	message := "message"
	// sign message
	signature := SignMessageWithKey(privateKey, message)

	// verify message
	if !VerifyMessageFromKey(publicKey, message, signature) {
		t.Error("Expected message to be verified")
	}

	// create wrong public key
	wrongPublicKey, _ := createKeysFromPassword("wrong password")
	// verify message with wrong public key
	if VerifyMessageFromKey(wrongPublicKey, message, signature) {
		t.Error("Expected message to not be verified")
	}

	// verify message with wrong message
	if VerifyMessageFromKey(publicKey, "wrong message", signature) {
		t.Error("Expected message to not be verified")
	}

	// create wrong signature
	wrongSignature := SignMessageWithKey(privateKey, "wrong message")
	// verify message with wrong signature
	if VerifyMessageFromKey(publicKey, message, wrongSignature) {
		t.Error("Expected message to not be verified")
	}
}

