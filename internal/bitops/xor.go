package bitops

import (
	"errors"
	"fmt"
)

var (
	ErrArgLengthMismatch = errors.New("argument length mismatch")
)

func XOR(args ...[]byte) error {
	for i := 1; i < len(args); i++ {
		if len(args[0]) != len(args[i]) {
			return fmt.Errorf("XOR: %w, want %d got %d", ErrArgLengthMismatch, len(args[0]), len(args[i]))
		}
	}
	for i := 1; i < len(args); i++ {
		for j := range args[0] {
			args[0][j] ^= args[i][j]
		}
	}
	return nil
}
