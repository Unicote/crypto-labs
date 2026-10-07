package modes

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidMode       = errors.New("invalid cipher mode")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

type Mode uint8

const (
	ECB Mode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

func IsValid(mode Mode) bool {
	return mode <= RandomDelta
}

type BlockCipher interface {
	BlockSize() int
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}

func Encrypt(mode Mode, algorithm BlockCipher, iv []byte, data []byte, workers int) ([]byte, []byte, error) {
	return crypt(mode, &runner{algorithm: algorithm, iv: iv, workers: workers}, data, false)
}

func Decrypt(mode Mode, algorithm BlockCipher, iv []byte, data []byte, workers int) ([]byte, []byte, error) {
	return crypt(mode, &runner{algorithm: algorithm, iv: iv, workers: workers}, data, true)
}

func crypt(mode Mode, c *runner, data []byte, decrypt bool) ([]byte, []byte, error) {
	if err := c.requireFullBlocks(data); err != nil {
		return nil, nil, err
	}
	result, err := c.run(mode, data, decrypt)
	if err != nil {
		return nil, nil, err
	}
	return result, c.iv, nil
}

func (r *runner) run(mode Mode, data []byte, decrypt bool) ([]byte, error) {
	switch mode {
	case ECB:
		if decrypt {
			return r.decryptECB(data)
		}
		return r.encryptECB(data)
	case CBC:
		if decrypt {
			return r.decryptCBC(data)
		}
		return r.encryptCBC(data)
	case PCBC:
		if decrypt {
			return r.decryptPCBC(data)
		}
		return r.encryptPCBC(data)
	case CFB:
		if decrypt {
			return r.decryptCFB(data)
		}
		return r.encryptCFB(data)
	case OFB:
		return r.cryptOFB(data)
	case CTR:
		return r.cryptCTR(data)
	case RandomDelta:
		return r.cryptRD(data)
	default:
		return nil, ErrInvalidMode
	}
}

type runner struct {
	algorithm BlockCipher
	iv        []byte
	workers   int
}

func (r *runner) blockSize() int {
	return r.algorithm.BlockSize()
}

func (r *runner) transformBlocks(data []byte, transform func(block []byte) ([]byte, error)) ([]byte, error) {
	blockSize := r.blockSize()
	result := make([]byte, len(data))
	err := r.runParallel(len(data)/blockSize, func(blockIndex int) error {
		start := blockIndex * blockSize
		transformed, err := transform(data[start : start+blockSize])
		if err != nil {
			return err
		}
		copy(result[start:start+blockSize], transformed)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *runner) runParallel(blocks int, task func(blockIndex int) error) error {
	jobs := make(chan int)
	var (
		waitGroup sync.WaitGroup
		once      sync.Once
		firstErr  error
	)

	for range min(r.workers, blocks) {
		waitGroup.Go(func() {
			for blockIndex := range jobs {
				if err := task(blockIndex); err != nil {
					once.Do(func() { firstErr = err })
				}
			}
		})
	}
	for blockIndex := range blocks {
		jobs <- blockIndex
	}
	close(jobs)
	waitGroup.Wait()
	return firstErr
}

func (r *runner) encryptBlock(block []byte) ([]byte, error) {
	return r.cryptBlock(r.algorithm.EncryptBlock, block)
}

func (r *runner) decryptBlock(block []byte) ([]byte, error) {
	return r.cryptBlock(r.algorithm.DecryptBlock, block)
}

func (r *runner) cryptBlock(transform func(block []byte) ([]byte, error), block []byte) ([]byte, error) {
	result, err := transform(block)
	if err != nil {
		return nil, err
	}
	if len(result) != r.blockSize() {
		return nil, fmt.Errorf("symmetric algorithm returned %d bytes, want %d", len(result), r.blockSize())
	}
	return result, nil
}

func (r *runner) requireFullBlocks(data []byte) error {
	if len(data)%r.blockSize() != 0 {
		return fmt.Errorf("%w: length %d is not a multiple of %d", ErrInvalidCiphertext, len(data), r.blockSize())
	}
	return nil
}
