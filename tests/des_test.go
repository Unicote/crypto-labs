package tests

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ariollex/crypto/algorithms/des"
	"github.com/ariollex/crypto/internal/cipher"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return result
}

func TestDESKnownVectors(t *testing.T) {
	tests := []struct{ name, key, plainText, cipherText string }{
		{"Grabbe", "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"},
		{"FIPS 81", "0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"},
		{"zero key", "0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm := des.NewDES()
			if err := algorithm.SetRoundKeys(decodeHex(t, tt.key)); err != nil {
				t.Fatalf("SetRoundKeys() error = %v", err)
			}
			plainText := decodeHex(t, tt.plainText)
			cipherText, err := algorithm.EncryptBlock(plainText)
			if err != nil {
				t.Fatalf("EncryptBlock() error = %v", err)
			}
			if want := decodeHex(t, tt.cipherText); !bytes.Equal(cipherText, want) {
				t.Fatalf("EncryptBlock() = % X, want % X", cipherText, want)
			}
			decrypted, err := algorithm.DecryptBlock(cipherText)
			if err != nil {
				t.Fatalf("DecryptBlock() error = %v", err)
			}
			if !bytes.Equal(decrypted, plainText) {
				t.Fatalf("DecryptBlock() = % X, want % X", decrypted, plainText)
			}
		})
	}
}

func TestDESModesAndPaddings(t *testing.T) {
	testModesAndPaddings(t, func() cipher.SymmetricAlgorithm { return des.NewDES() }, decodeHex(t, "133457799BBCDFF1"))
}
