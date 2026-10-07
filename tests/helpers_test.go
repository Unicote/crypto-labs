package tests

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/cipher/modes"
	"github.com/ariollex/crypto/internal/cipher/paddings"
)

var allModes = []modes.Mode{modes.ECB, modes.CBC, modes.PCBC, modes.CFB, modes.OFB, modes.CTR, modes.RandomDelta}

var allPaddings = []paddings.Mode{paddings.Zeros, paddings.ANSIX923, paddings.PKCS7, paddings.ISO10126}

func ivFor(mode modes.Mode, iv []byte) []byte {
	if mode == modes.ECB {
		return nil
	}
	return iv
}

func cipherModeName(mode modes.Mode) string {
	return [...]string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"}[mode]
}

func paddingName(padding paddings.Mode) string {
	return [...]string{"Zeros", "ANSIX923", "PKCS7", "ISO10126"}[padding]
}

func receiveBytes(t *testing.T, resultChannel <-chan cipher.BytesResult) []byte {
	t.Helper()
	result, open := <-resultChannel
	if !open {
		t.Fatal("result channel closed without a result")
	}
	if result.Err != nil {
		t.Fatalf("asynchronous operation returned an error: %v", result.Err)
	}
	return result.Data
}

func randomBytes(random *rand.Rand, size int) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = byte(random.Uint32())
	}
	return result
}

func testModesAndPaddings(t *testing.T, newAlgorithm func() cipher.SymmetricAlgorithm, key []byte) {
	blockSize := newAlgorithm().BlockSize()
	iv := randomBytes(rand.New(rand.NewPCG(1, 2)), blockSize)
	message := []byte("Encrypt and decrypt this message in every mode with every padding.")

	for _, mode := range allModes {
		for _, padding := range allPaddings {
			t.Run(cipherModeName(mode)+"/"+paddingName(padding), func(t *testing.T) {
				context, err := cipher.NewContext(newAlgorithm(), key, mode, padding, ivFor(mode, iv))
				if err != nil {
					t.Fatalf("NewContext() error = %v", err)
				}
				for _, size := range []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 3*blockSize + 1} {
					input := message[:size]
					encrypted := receiveBytes(t, context.Encrypt(input))
					if len(encrypted)%blockSize != 0 {
						t.Fatalf("%d bytes: ciphertext length %d is not a multiple of %d", size, len(encrypted), blockSize)
					}
					decrypted := receiveBytes(t, context.Decrypt(encrypted))
					if !bytes.Equal(decrypted, input) {
						t.Fatalf("%d bytes: Decrypt(Encrypt(input)) = %q, want %q", size, decrypted, input)
					}
				}
			})
		}
	}
}
