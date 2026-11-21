package rsa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/numtheory"
	"github.com/ariollex/crypto/internal/primality"
)

var (
	ErrUnknownTest    = errors.New("unknown primality test")
	ErrInvalidMessage = errors.New("message must be in [0, N)")
)

var (
	one          = big.NewInt(1)
	three        = big.NewInt(3)
	wienerFactor = big.NewInt(81)
)

type PrimalityTest int

const (
	Fermat PrimalityTest = iota
	SolovayStrassen
	MillerRabin
)

var primalityTests = [...]primality.Test{
	primality.Fermat,
	primality.SolovayStrassen,
	primality.MillerRabin,
}

type Key struct {
	Exponent, Modulus *big.Int
}

//#region Key Generation

type KeyGenerator struct {
	test        primality.Test
	probability float64
	bits        int
}

func NewKeyGenerator(test PrimalityTest, probability float64, bits int) (*KeyGenerator, error) {
	if test < Fermat || test > MillerRabin {
		return nil, ErrUnknownTest
	}
	return &KeyGenerator{primalityTests[test], probability, bits}, nil
}

func (g *KeyGenerator) GeneratePrimes() (p, q *big.Int, err error) {
	for {
		if p, err = primality.Generate(g.test, g.probability, g.bits); err != nil {
			return nil, nil, err
		}
		if q, err = primality.Generate(g.test, g.probability, g.bits); err != nil {
			return nil, nil, err
		}
		if new(big.Int).Sub(p, q).BitLen() >= g.bits-2 {
			return p, q, nil
		}
	}
}

func (g *KeyGenerator) Generate() (public, private Key, err error) {
	p, q, err := g.GeneratePrimes()
	if err != nil {
		return Key{}, Key{}, err
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(p.Sub(p, one), q.Sub(q, one))
	for {
		e, err := rand.Int(rand.Reader, phi)
		if err != nil {
			return Key{}, Key{}, err
		}
		if e.Cmp(three) < 0 {
			continue
		}
		d, err := numtheory.InverseElement(e, phi)
		if err != nil {
			continue
		}
		d4 := new(big.Int).Mul(d, d)
		if d4.Mul(d4, d4).Mul(d4, wienerFactor).Cmp(n) > 0 {
			return Key{e, n}, Key{d, n}, nil
		}
	}
}

//#endregion Key Generation

//#region RSA

type RSA struct {
	generator       *KeyGenerator
	Public, Private Key
}

func New(test PrimalityTest, probability float64, bits int) (*RSA, error) {
	generator, err := NewKeyGenerator(test, probability, bits)
	if err != nil {
		return nil, err
	}
	r := &RSA{generator: generator}
	if err = r.GenerateKeys(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RSA) GenerateKeys() (err error) {
	r.Public, r.Private, err = r.generator.Generate()
	return err
}

func (r *RSA) Encrypt(message *big.Int) (*big.Int, error) {
	return crypt(message, r.Public)
}

func (r *RSA) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	return crypt(ciphertext, r.Private)
}

func crypt(value *big.Int, key Key) (*big.Int, error) {
	if value.Sign() < 0 || value.Cmp(key.Modulus) >= 0 {
		return nil, ErrInvalidMessage
	}
	return numtheory.ModPow(value, key.Exponent, key.Modulus), nil
}

//#endregion RSA

func (r *RSA) EncryptFile(input, output string) <-chan cipher.BytesResult {
	return r.transformFile(input, output, false)
}

func (r *RSA) DecryptFile(input, output string) <-chan cipher.BytesResult {
	return r.transformFile(input, output, true)
}

func (r *RSA) transformFile(input, output string, decrypt bool) <-chan cipher.BytesResult {
	return cipher.TransformFile(input, output, func(source io.Reader, target io.Writer, size int64) error {
		key := r.Public
		if decrypt {
			key = r.Private
		}
		bits := key.Modulus.BitLen()
		plainSize := (bits - 1) / 8
		if plainSize < 2 {
			return fmt.Errorf("RSA modulus is too small for file blocks")
		}
		if size == 0 {
			return nil
		}
		encoded := make([]byte, (bits+7)/8)

		if decrypt {
			if size%int64(len(encoded)) != 0 {
				return fmt.Errorf("read RSA ciphertext block: %w", io.ErrUnexpectedEOF)
			}
			return cipher.TransformChunks(source, target, size, encoded, func(input []byte, _ bool) ([]byte, error) {
				value, err := crypt(new(big.Int).SetBytes(input), key)
				if err != nil {
					return nil, err
				}
				block := value.Bytes()
				if len(block) < 2 || len(block) > plainSize || block[0] != 1 {
					return nil, fmt.Errorf("invalid RSA plaintext block")
				}
				return block[1:], nil
			})
		}

		plain := make([]byte, plainSize)
		plain[0] = 1
		return cipher.TransformChunks(source, target, size, plain[1:], func(input []byte, _ bool) ([]byte, error) {
			value, err := crypt(new(big.Int).SetBytes(plain[:len(input)+1]), key)
			if err != nil {
				return nil, err
			}
			return value.FillBytes(encoded), nil
		})
	})
}
