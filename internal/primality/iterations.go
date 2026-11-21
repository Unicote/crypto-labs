package primality

import (
	"math/big"

	"github.com/ariollex/crypto/internal/numtheory"
)

func fermat(n, a *big.Int) bool {
	return numtheory.ModPow(a, new(big.Int).Sub(n, one), n).Cmp(one) == 0
}

func solovayStrassen(n, a *big.Int) bool {
	jacobi, _ := numtheory.Jacobi(a, n)
	if jacobi == 0 {
		return false
	}
	expected := big.NewInt(int64(jacobi))
	exponent := new(big.Int).Rsh(n, 1)
	return numtheory.ModPow(a, exponent, n).Cmp(expected.Mod(expected, n)) == 0
}

func millerRabin(n, a *big.Int) bool {
	nMinus1 := new(big.Int).Sub(n, one)
	d := nMinus1.TrailingZeroBits()
	x := numtheory.ModPow(a, new(big.Int).Rsh(nMinus1, d), n)
	if x.Cmp(one) == 0 {
		return true
	}
	for range d {
		if x.Cmp(nMinus1) == 0 {
			return true
		}
		x.Mod(x.Mul(x, x), n)
	}
	return false
}
