package tests

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/ariollex/crypto/algorithms/deal"
	"github.com/ariollex/crypto/internal/cipher"
)

func TestDEALModesAndPaddings(t *testing.T) {
	random := rand.New(rand.NewPCG(3, 4))
	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("DEAL-%d", keySize*8), func(t *testing.T) {
			testModesAndPaddings(t, func() cipher.SymmetricAlgorithm { return deal.NewDEAL() }, randomBytes(random, keySize))
		})
	}
}
