package cipher

import (
	"bytes"
	"fmt"

	"github.com/ariollex/crypto/internal/cipher/modes"
	"github.com/ariollex/crypto/internal/cipher/paddings"
)

type chunkOperation func(data, iv []byte, last bool) ([]byte, []byte, error)

func (c *Context) Encrypt(data []byte) <-chan BytesResult {
	return c.cryptData(data, c.encryptChunk)
}

func (c *Context) Decrypt(data []byte) <-chan BytesResult {
	return c.cryptData(data, c.decryptChunk)
}

func (c *Context) cryptData(data []byte, operation chunkOperation) <-chan BytesResult {
	input := bytes.Clone(data)
	ch := make(chan BytesResult, 1)
	go func() {
		result, _, err := operation(input, c.iv, true)
		ch <- BytesResult{Data: result, Err: err}
		close(ch)
	}()
	return ch
}

func (c *Context) encryptChunk(data, iv []byte, last bool) ([]byte, []byte, error) {
	if last {
		var err error
		data, err = paddings.Pad(c.padding, data, c.algorithm.BlockSize())
		if err != nil {
			return nil, nil, err
		}
	}
	return modes.Encrypt(c.mode, c.algorithm, iv, data, c.workers)
}

func (c *Context) decryptChunk(data, iv []byte, last bool) ([]byte, []byte, error) {
	result, next, err := modes.Decrypt(c.mode, c.algorithm, iv, data, c.workers)
	if err != nil || !last {
		return result, next, err
	}

	result, err = paddings.Unpad(c.padding, result, c.algorithm.BlockSize())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", modes.ErrInvalidCiphertext, err)
	}
	return result, next, nil
}
