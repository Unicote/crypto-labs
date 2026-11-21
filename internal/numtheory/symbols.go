package numtheory

import "math/big"

func Legendre(a, p *big.Int) (int, error) {
	if p.Cmp(two) <= 0 || p.Bit(0) == 0 {
		return 0, ErrInvalidModulus
	}
	pMinus1 := new(big.Int).Sub(p, one)
	switch ModPow(a, new(big.Int).Rsh(pMinus1, 1), p).Cmp(one) {
	case -1:
		return 0, nil
	case 0:
		return 1, nil
	}
	return -1, nil
}

func Jacobi(a, n *big.Int) (int, error) {
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		return 0, ErrInvalidModulus
	}
	a, n = new(big.Int).Mod(a, n), new(big.Int).Set(n)
	result := 1
	for a.Sign() != 0 {
		zeros := a.TrailingZeroBits()
		a.Rsh(a, zeros)
		if zeros%2 == 1 && n.Bit(1) != n.Bit(2) { // 3, 5 (mod 8)
			result = -result
		}
		if a.Bit(1) == 1 && n.Bit(1) == 1 { //  3 (mod 4)
			result = -result
		}
		a, n = n.Mod(n, a), a
	}
	if n.Cmp(one) != 0 {
		return 0, nil
	}
	return result, nil
}
