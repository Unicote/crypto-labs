package numtheory

import "math/big"

func ModPow(x, y, m *big.Int) *big.Int {
	if x == y {
		y = new(big.Int).Set(y)
	}
	if x == m {
		m = new(big.Int).Set(m)
	}
	factor := new(big.Int).Mod(x, m)
	x.SetUint64(1)

	for i := y.BitLen() - 1; i >= 0; i-- {
		x.Mod(x.Mul(x, x), m)
		if y.Bit(i) == 1 {
			x.Mod(x.Mul(x, factor), m)
		}
	}

	return x.Mod(x, m)
}

func Sqrt(n *big.Int) *big.Int {
	if n.Sign() <= 0 {
		return new(big.Int)
	}
	x := new(big.Int).Lsh(one, uint(n.BitLen()+1)/2)
	for {
		next := new(big.Int).Add(x, new(big.Int).Quo(n, x))
		next.Rsh(next, 1)
		if next.Cmp(x) >= 0 {
			return x
		}
		x = next
	}
}
