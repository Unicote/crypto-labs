package numtheory

import "math/big"

func GCD(x, y *big.Int) *big.Int {
	x, y = new(big.Int).Abs(x), new(big.Int).Abs(y)
	for y.Sign() != 0 {
		x, y = y, x.Mod(x, y)
	}
	return x
}

func ExtendedGCD(x, y *big.Int) (*big.Int, *big.Int, *big.Int) {
	r0, r1 := new(big.Int).Set(x), new(big.Int).Set(y)
	s0, s1 := big.NewInt(1), big.NewInt(0)
	rem := new(big.Int)

	var q, tmp big.Int
	for r1.Sign() != 0 {
		q.QuoRem(r0, r1, rem)
		r0, r1, rem = r1, rem, r0 // r0 mem re-use

		tmp.Mul(&q, s1)
		s0, s1 = s1, s0.Sub(s0, &tmp)
	}

	if r0.Sign() < 0 {
		r0.Neg(r0)
		s0.Neg(s0)
	}

	if y.Sign() != 0 {
		tmp.Mul(s0, x)
		tmp.Sub(r0, &tmp)
		s1.Quo(&tmp, y) // s1 memory re-use
	}

	return r0, s0, s1
}

func BinaryGCD(a, b *big.Int) *big.Int {
	a, b = new(big.Int).Abs(a), new(big.Int).Abs(b)
	if a.Sign() == 0 {
		return b
	}
	if b.Sign() == 0 {
		return a
	}
	shift := min(a.TrailingZeroBits(), b.TrailingZeroBits())
	a.Rsh(a, a.TrailingZeroBits())
	for b.Sign() != 0 {
		b.Rsh(b, b.TrailingZeroBits())
		if a.Cmp(b) > 0 {
			a, b = b, a
		}
		b.Sub(b, a)
	}
	return a.Lsh(a, shift)
}

func InverseElement(x, m *big.Int) (*big.Int, error) {
	d, x, _ := ExtendedGCD(x, m)
	if d.Cmp(one) != 0 {
		return nil, ErrNotInvertible
	}
	return x.Mod(x, m), nil
}
