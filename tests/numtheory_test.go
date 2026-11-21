package tests

import (
	"math/big"
	"testing"

	"github.com/ariollex/crypto/internal/numtheory"
)

func TestGCD(t *testing.T) {
	cases := []struct{ a, b, want int64 }{
		{240, 46, 2}, {46, 240, 2}, {17, 5, 1}, {0, 9, 9}, {9, 0, 9}, {0, 0, 0}, {-12, 18, 6}, {1 << 40, 1 << 20 * 3, 1 << 20},
	}
	for _, c := range cases {
		a, b := big.NewInt(c.a), big.NewInt(c.b)
		for name, gcd := range map[string]func(a, b *big.Int) *big.Int{"Euclid": numtheory.GCD, "Binary": numtheory.BinaryGCD} {
			if got := gcd(a, b); got.Int64() != c.want {
				t.Errorf("%s(%d, %d) = %v, want %d", name, c.a, c.b, got, c.want)
			}
		}
		d, x, y := numtheory.ExtendedGCD(a, b)
		bezout := new(big.Int).Add(new(big.Int).Mul(a, x), new(big.Int).Mul(b, y))
		if d.Int64() != c.want || bezout.Cmp(d) != 0 {
			t.Errorf("ExtendedGCD(%d, %d) = %v, %v, %v", c.a, c.b, d, x, y)
		}
	}
}

func TestModInverse(t *testing.T) {
	inverse, err := numtheory.InverseElement(big.NewInt(17), big.NewInt(3120))
	if err != nil || inverse.Int64() != 2753 {
		t.Errorf("ModInverse(17, 3120) = %v, %v, want 2753", inverse, err)
	}
	if _, err = numtheory.InverseElement(big.NewInt(6), big.NewInt(9)); err == nil {
		t.Error("ModInverse(6, 9) error = nil")
	}
}

func TestModPow(t *testing.T) {
	cases := []struct{ base, exponent, modulus int64 }{
		{1003, 719, 97}, {52, 67, 1000}, {2, 0, 7}, {5, 3, 1}, {-3, 5, 11}, {123456789, 987654321, 1000000007},
	}
	for _, c := range cases {
		base, exponent, modulus := big.NewInt(c.base), big.NewInt(c.exponent), big.NewInt(c.modulus)
		want := new(big.Int).Exp(base, exponent, modulus)
		if got := numtheory.ModPow(base, exponent, modulus); got.Cmp(want) != 0 {
			t.Errorf("ModPow(%d, %d, %d) = %v, want %v", c.base, c.exponent, c.modulus, got, want)
		}
	}
}

func TestSqrt(t *testing.T) {
	for _, n := range []int64{0, 1, 2, 3, 4, 15, 16, 17, 1 << 62} {
		want := new(big.Int).Sqrt(big.NewInt(n))
		if got := numtheory.Sqrt(big.NewInt(n)); got.Cmp(want) != 0 {
			t.Errorf("Sqrt(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestLegendreAndJacobi(t *testing.T) {
	for _, n := range []int64{3, 5, 7, 11, 13, 9907} {
		for a := int64(-20); a <= 40; a++ {
			want := big.Jacobi(big.NewInt(a), big.NewInt(n))
			got, err := numtheory.Legendre(big.NewInt(a), big.NewInt(n))
			if err != nil || got != want {
				t.Errorf("Legendre(%d, %d) = %d, %v, want %d", a, n, got, err, want)
			}
		}
	}
	for n := int64(1); n < 200; n += 2 {
		for a := int64(-30); a <= 60; a++ {
			want := big.Jacobi(big.NewInt(a), big.NewInt(n))
			got, err := numtheory.Jacobi(big.NewInt(a), big.NewInt(n))
			if err != nil || got != want {
				t.Errorf("Jacobi(%d, %d) = %d, %v, want %d", a, n, got, err, want)
			}
		}
	}
	if _, err := numtheory.Jacobi(big.NewInt(3), big.NewInt(8)); err == nil {
		t.Error("Jacobi(3, 8) error = nil")
	}
	if _, err := numtheory.Legendre(big.NewInt(3), big.NewInt(2)); err == nil {
		t.Error("Legendre(3, 2) error = nil")
	}
}

func TestEuler(t *testing.T) {
	want := []int64{1, 1, 2, 2, 4, 2, 6, 4, 6, 4, 10, 4, 12, 6, 8, 8, 16, 6, 18, 8, 12, 10, 22, 8, 20, 12, 18, 12, 28, 8, 30, 16, 20, 16, 24, 12}
	functions := map[string]func(*big.Int) (*big.Int, error){
		"Definition": numtheory.EulerDefinition, "Factorization": numtheory.EulerFactorization, "Fourier": numtheory.EulerFourier,
	}
	for name, euler := range functions {
		for i, phi := range want {
			if got, err := euler(big.NewInt(int64(i + 1))); err != nil || got.Int64() != phi {
				t.Errorf("Euler%s(%d) = %v, %v, want %d", name, i+1, got, err, phi)
			}
		}
		if got, err := euler(big.NewInt(1000)); err != nil || got.Int64() != 400 {
			t.Errorf("Euler%s(1000) = %v, %v, want 400", name, got, err)
		}
		if _, err := euler(big.NewInt(0)); err == nil {
			t.Errorf("Euler%s(0) error = nil", name)
		}
	}
}

func TestCarmichael(t *testing.T) {
	cases := []struct{ n, want int64 }{
		{1, 1}, {2, 1}, {4, 2}, {8, 2}, {16, 4}, {9, 6}, {15, 4}, {36, 6}, {561, 80}, {1000, 100}, {65537, 65536},
	}
	for _, c := range cases {
		if got, err := numtheory.Carmichael(big.NewInt(c.n)); err != nil || got.Int64() != c.want {
			t.Errorf("Carmichael(%d) = %v, %v, want %d", c.n, got, err, c.want)
		}
	}
}
