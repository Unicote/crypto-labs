package numtheory

import (
	"errors"
	"math/big"
)

var (
	ErrInvalidModulus = errors.New("modulus must be odd and positive")
	ErrNotInvertible  = errors.New("number is not invertible modulo m")
	ErrNotPositive    = errors.New("number must be positive")
)

var (
	one = big.NewInt(1)
	two = big.NewInt(2)
)
