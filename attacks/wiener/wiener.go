package wiener

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/ariollex/crypto/algorithms/rsa"
	"github.com/ariollex/crypto/internal/numtheory"
)

var ErrNotVulnerable = errors.New("key is not vulnerable to Wiener's attack")

var (
	one   = big.NewInt(1)
	three = big.NewInt(3)
)

func Attack(public rsa.Key) (d, phi *big.Int, convergents []*big.Rat, err error) {
	e, n := public.Exponent, public.Modulus
	numerator, denominator := new(big.Int).Set(e), new(big.Int).Set(n)
	previousK, k := big.NewInt(0), big.NewInt(1) // p(-2), p(-1)
	previousD, d := big.NewInt(1), big.NewInt(0) // q(-2), q(-1)
	for denominator.Sign() != 0 {
		a, remainder := new(big.Int).QuoRem(numerator, denominator, new(big.Int))
		numerator, denominator = denominator, remainder
		previousK, k = k, new(big.Int).Add(new(big.Int).Mul(a, k), previousK)
		previousD, d = d, new(big.Int).Add(new(big.Int).Mul(a, d), previousD)
		convergents = append(convergents, new(big.Rat).SetFrac(k, d))
		if phi = phiFromConvergent(e, n, k, d); phi != nil {
			return d, phi, convergents, nil
		}
	}
	return nil, nil, convergents, ErrNotVulnerable
}

func phiFromConvergent(e, n, k, d *big.Int) *big.Int {
	if k.Sign() == 0 {
		return nil
	}
	phi, remainder := new(big.Int).QuoRem(new(big.Int).Sub(new(big.Int).Mul(e, d), one), k, new(big.Int))
	if remainder.Sign() != 0 {
		return nil
	}
	sum := new(big.Int).Add(new(big.Int).Sub(n, phi), one) // p + q
	discriminant := new(big.Int).Sub(new(big.Int).Mul(sum, sum), new(big.Int).Lsh(n, 2))
	if discriminant.Sign() < 0 {
		return nil
	}
	root := numtheory.Sqrt(discriminant)
	if new(big.Int).Mul(root, root).Cmp(discriminant) != 0 {
		return nil
	}
	p := new(big.Int).Add(sum, root)
	q := new(big.Int).Sub(sum, root)
	if new(big.Int).Mul(p.Rsh(p, 1), q.Rsh(q, 1)).Cmp(n) != 0 {
		return nil
	}
	return phi
}

func GenerateVulnerable(test rsa.PrimalityTest, probability float64, bits int) (public, private rsa.Key, err error) {
	generator, err := rsa.NewKeyGenerator(test, probability, bits)
	if err != nil {
		return rsa.Key{}, rsa.Key{}, err
	}
	p, q, err := generator.GeneratePrimes()
	if err != nil {
		return rsa.Key{}, rsa.Key{}, err
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(p.Sub(p, one), q.Sub(q, one))
	bound := new(big.Int).Quo(numtheory.Sqrt(numtheory.Sqrt(n)), three)
	for {
		d, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return rsa.Key{}, rsa.Key{}, err
		}
		if d.Cmp(one) <= 0 {
			continue
		}
		e, err := numtheory.InverseElement(d, phi)
		if err != nil {
			continue
		}
		return rsa.Key{Exponent: e, Modulus: n}, rsa.Key{Exponent: d, Modulus: n}, nil
	}
}
