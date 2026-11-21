package tests

import (
	"math/big"
	"testing"

	"github.com/ariollex/crypto/algorithms/rsa"
	"github.com/ariollex/crypto/attacks/wiener"
)

func TestRSA(t *testing.T) {
	message := new(big.Int).SetBytes([]byte("Encrypt and decrypt this message with RSA."))
	for _, test := range []rsa.PrimalityTest{rsa.Fermat, rsa.SolovayStrassen, rsa.MillerRabin} {
		service, err := rsa.New(test, 0.99, 256)
		if err != nil {
			t.Fatalf("New(%d) error = %v", test, err)
		}
		for range 3 {
			public, private := service.Public, service.Private
			if public.Modulus.BitLen() < 511 {
				t.Errorf("modulus has %d bits", public.Modulus.BitLen())
			}
			if _, _, _, err = wiener.Attack(public); err == nil {
				t.Error("Wiener's attack succeeded on a generated key")
			}
			ciphertext, err := service.Encrypt(message)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			decrypted, err := service.Decrypt(ciphertext)
			if err != nil || decrypted.Cmp(message) != 0 {
				t.Fatalf("Decrypt(Encrypt(m)) = %v, %v, want %v", decrypted, err, message)
			}
			if err = service.GenerateKeys(); err != nil {
				t.Fatalf("GenerateKeys() error = %v", err)
			}
			if service.Public.Modulus.Cmp(public.Modulus) == 0 || service.Private.Exponent.Cmp(private.Exponent) == 0 {
				t.Error("GenerateKeys() returned the same key pair")
			}
		}
		if _, err = service.Encrypt(service.Public.Modulus); err == nil {
			t.Error("Encrypt(N) error = nil")
		}
	}
	if _, err := rsa.New(rsa.MillerRabin+1, 0.99, 256); err == nil {
		t.Error("New(unknown test) error = nil")
	}
	if _, err := rsa.New(rsa.MillerRabin, 0.3, 256); err == nil {
		t.Error("New(probability 0.3) error = nil")
	}
}

func TestWienerAttack(t *testing.T) {
	for _, bits := range []int{64, 256, 512} {
		public, private, err := wiener.GenerateVulnerable(rsa.MillerRabin, 0.99, bits)
		if err != nil {
			t.Fatalf("GenerateVulnerable(%d) error = %v", bits, err)
		}
		d, phi, convergents, err := wiener.Attack(public)
		if err != nil {
			t.Fatalf("Attack() error = %v", err)
		}
		if d.Cmp(private.Exponent) != 0 {
			t.Errorf("Attack() d = %v, want %v", d, private.Exponent)
		}
		last := convergents[len(convergents)-1]
		if len(convergents) < 2 || last.Denom().Cmp(d) != 0 {
			t.Errorf("Attack() convergents = %v", convergents)
		}
		check := new(big.Int).Mul(public.Exponent, d)
		if check.Mod(check, phi).Int64() != 1 {
			t.Errorf("e*d mod phi = %v, want 1", check)
		}
	}
}
