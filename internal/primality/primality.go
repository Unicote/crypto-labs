package primality

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	ErrInvalidProbability = errors.New("probability must be in [0.5, 1)")
	ErrInvalidBits        = errors.New("bit length must be at least 16")
)

const minBits = 16

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
)

type Test interface {
	IsProbablyPrime(n *big.Int, probability float64) (bool, error)
}

type test struct {
	iteration func(n, a *big.Int) bool
	errorRate float64
}

var (
	Fermat          Test = test{fermat, 1. / 2}
	SolovayStrassen Test = test{solovayStrassen, 1. / 2}
	MillerRabin     Test = test{millerRabin, 1. / 4}
)

func (t test) IsProbablyPrime(n *big.Int, probability float64) (bool, error) {
	if probability < 0.5 || probability >= 1 {
		return false, ErrInvalidProbability
	}
	if n.Cmp(four) < 0 {
		return n.Cmp(one) > 0, nil
	}
	if n.Bit(0) == 0 {
		return false, nil
	}
	bound := new(big.Int).Sub(n, three)
	for chance := 1.0; chance > 1-probability; chance *= t.errorRate {
		a, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return false, err
		}
		if !t.iteration(n, a.Add(a, two)) { // a in [2, n-2]
			return false, nil
		}
	}
	return true, nil
}

func Generate(test Test, probability float64, bits int) (*big.Int, error) {
	if bits < minBits {
		return nil, ErrInvalidBits
	}
	bound := new(big.Int).Lsh(one, uint(bits-1))
	for {
		candidate, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return nil, err
		}
		candidate.SetBit(candidate, bits-1, 1)
		candidate.SetBit(candidate, 0, 1)
		prime, err := test.IsProbablyPrime(candidate, probability)
		if err != nil {
			return nil, err
		}
		if prime {
			return candidate, nil
		}
	}
}
