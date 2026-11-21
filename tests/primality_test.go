package tests

import (
	"math/big"
	"testing"

	"github.com/ariollex/crypto/internal/primality"
)

var primalityTests = map[string]primality.Test{
	"Fermat": primality.Fermat, "SolovayStrassen": primality.SolovayStrassen, "MillerRabin": primality.MillerRabin,
}

func TestPrimalityTests(t *testing.T) {
	primes := []int64{2, 3, 5, 7, 11, 97, 7919, 9907, 65537, 1000000007, 2305843009213693951}
	composites := []int64{0, 1, 4, 9, 15, 91, 7917, 1000000005, 2305843009213693953}
	strongPseudoprimes := []int64{561, 1105, 1729, 2465, 3215031751}
	for name, test := range primalityTests {
		t.Run(name, func(t *testing.T) {
			for _, n := range primes {
				if prime, err := test.IsProbablyPrime(big.NewInt(n), 0.999); err != nil || !prime {
					t.Errorf("IsProbablyPrime(%d) = %v, %v, want true", n, prime, err)
				}
			}
			for _, n := range composites {
				if prime, err := test.IsProbablyPrime(big.NewInt(n), 0.999); err != nil || prime {
					t.Errorf("IsProbablyPrime(%d) = %v, %v, want false", n, prime, err)
				}
			}
			for _, probability := range []float64{0.49, 1, 2} {
				if _, err := test.IsProbablyPrime(big.NewInt(7), probability); err == nil {
					t.Errorf("IsProbablyPrime(7, %v) error = nil", probability)
				}
			}
		})
	}
	for _, test := range []primality.Test{primality.SolovayStrassen, primality.MillerRabin} {
		for _, n := range strongPseudoprimes {
			if prime, _ := test.IsProbablyPrime(big.NewInt(n), 0.999999); prime {
				t.Errorf("IsProbablyPrime(%d) = true for a Carmichael number", n)
			}
		}
	}
}

func TestGeneratePrime(t *testing.T) {
	for name, test := range primalityTests {
		prime, err := primality.Generate(test, 0.99, 256)
		if err != nil || prime.BitLen() != 256 || !prime.ProbablyPrime(20) {
			t.Errorf("%s: Generate() = %v, %v", name, prime, err)
		}
	}
	if _, err := primality.Generate(primality.MillerRabin, 0.99, 8); err == nil {
		t.Error("Generate(8 bits) error = nil")
	}
}
