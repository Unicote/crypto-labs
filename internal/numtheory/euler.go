package numtheory

import (
	"math"
	"math/big"
)

func EulerDefinition(n *big.Int) (*big.Int, error) {
	if n.Sign() <= 0 {
		return nil, ErrNotPositive
	}
	result := new(big.Int)
	for k := big.NewInt(1); k.Cmp(n) <= 0; k.Add(k, one) {
		if GCD(k, n).Cmp(one) == 0 {
			result.Add(result, one)
		}
	}
	return result, nil
}

func EulerFactorization(n *big.Int) (*big.Int, error) {
	primes, _, err := factorize(n)
	if err != nil {
		return nil, err
	}
	result := new(big.Int).Set(n)
	for _, p := range primes {
		result.Quo(result, p)
		result.Mul(result, new(big.Int).Sub(p, one))
	}
	return result, nil
}

func EulerFourier(n *big.Int) (*big.Int, error) {
	if n.Sign() <= 0 {
		return nil, ErrNotPositive
	}
	sum := 0.0
	for k := big.NewInt(1); k.Cmp(n) <= 0; k.Add(k, one) {
		gcd, _ := new(big.Float).SetInt(GCD(k, n)).Float64()
		ratio, _ := new(big.Rat).SetFrac(k, n).Float64()
		sum += gcd * math.Cos(2*math.Pi*ratio)
	}
	result, _ := big.NewFloat(math.Round(sum)).Int(nil)
	return result, nil
}

func Carmichael(n *big.Int) (*big.Int, error) {
	primes, powers, err := factorize(n)
	if err != nil {
		return nil, err
	}
	result := big.NewInt(1)
	for i, p := range primes {
		lambda := new(big.Int).Sub(p, one)
		for range powers[i] - 1 {
			lambda.Mul(lambda, p)
		}
		if p.Cmp(two) == 0 && powers[i] >= 3 {
			lambda.Rsh(lambda, 1)
		}
		result.Mul(result.Quo(result, GCD(result, lambda)), lambda)
	}
	return result, nil
}

func factorize(n *big.Int) (primes []*big.Int, powers []int, err error) {
	if n.Sign() <= 0 {
		return nil, nil, ErrNotPositive
	}
	n = new(big.Int).Set(n)
	quotient, remainder := new(big.Int), new(big.Int)
	for p := big.NewInt(2); new(big.Int).Mul(p, p).Cmp(n) <= 0; p.Add(p, one) {
		power := 0
		for quotient.QuoRem(n, p, remainder); remainder.Sign() == 0; quotient.QuoRem(n, p, remainder) {
			n.Set(quotient)
			power++
		}
		if power > 0 {
			primes = append(primes, new(big.Int).Set(p))
			powers = append(powers, power)
		}
	}
	if n.Cmp(one) > 0 {
		primes = append(primes, n)
		powers = append(powers, 1)
	}
	return primes, powers, nil
}
