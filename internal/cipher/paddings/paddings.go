package paddings

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidMode    = errors.New("invalid padding mode")
	ErrInvalidPadding = errors.New("invalid padding")
)

type Mode uint8

const (
	Zeros Mode = iota
	ANSIX923
	PKCS7
	ISO10126
)

func IsValid(mode Mode) bool {
	return mode <= ISO10126
}

func Pad(mode Mode, data []byte, blockSize int) ([]byte, error) {
	switch mode {
	case Zeros:
		return padZeros(data, blockSize), nil
	case ANSIX923:
		return padANSIX923(data, blockSize), nil
	case PKCS7:
		return padPKCS7(data, blockSize), nil
	case ISO10126:
		return padISO10126(data, blockSize), nil
	default:
		return nil, ErrInvalidMode
	}
}

func Unpad(mode Mode, data []byte, blockSize int) ([]byte, error) {
	switch mode {
	case Zeros:
		return unpadZeros(data)
	case ANSIX923:
		return unpadANSIX923(data, blockSize)
	case PKCS7:
		return unpadPKCS7(data, blockSize)
	case ISO10126:
		return unpadISO10126(data, blockSize)
	default:
		return nil, ErrInvalidMode
	}
}

func paddingLength(data []byte, blockSize int) int {
	return blockSize - len(data)%blockSize
}

func readPaddingLength(data []byte, blockSize int) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("%w: missing padding", ErrInvalidPadding)
	}
	result := int(data[len(data)-1])
	if result < 1 || result > blockSize {
		return 0, fmt.Errorf("%w: invalid padding length", ErrInvalidPadding)
	}
	return result, nil
}
