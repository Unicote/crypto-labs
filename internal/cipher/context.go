package cipher

import (
	"bytes"
	"fmt"
	"runtime"

	"github.com/ariollex/crypto/internal/cipher/modes"
	"github.com/ariollex/crypto/internal/cipher/paddings"
)

type Context struct {
	algorithm SymmetricAlgorithm
	mode      modes.Mode
	padding   paddings.Mode
	iv        []byte
	workers   int
}

type BytesResult struct {
	Data []byte
	Err  error
}

// region Options

type ContextOption func(*contextConfig) error

type contextConfig struct {
	workers int
}

func SetWorkers(workers int) ContextOption {
	return func(config *contextConfig) error {
		if workers <= 0 {
			return ErrInvalidWorkers
		}
		config.workers = workers
		return nil
	}
}

//endregion Options

func NewContext(algorithm SymmetricAlgorithm, key RoundKey, mode modes.Mode, padding paddings.Mode, iv []byte, options ...ContextOption) (*Context, error) {
	if algorithm == nil {
		return nil, ErrNilAlgorithm
	}
	if !modes.IsValid(mode) {
		return nil, modes.ErrInvalidMode
	}
	if !paddings.IsValid(padding) {
		return nil, paddings.ErrInvalidMode
	}

	blockSize := algorithm.BlockSize()
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidBlockSize, blockSize)
	}
	ivSize := blockSize
	if mode == modes.ECB {
		ivSize = 0
	}
	if len(iv) != ivSize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidIV, len(iv), ivSize)
	}

	config := contextConfig{workers: runtime.GOMAXPROCS(0)}
	for _, option := range options {
		if err := option(&config); err != nil {
			return nil, err
		}
	}

	if err := algorithm.SetRoundKeys(key); err != nil {
		return nil, err
	}

	ivCopy := bytes.Clone(iv)
	if mode == modes.CTR {
		clear(ivCopy[:blockSize/2])
	}
	return &Context{algorithm: algorithm, mode: mode, padding: padding, iv: ivCopy, workers: config.workers}, nil
}
