package cipher

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const fileChunkSize = 64 * 1024

func (c *Context) EncryptFile(inputPath, outputPath string) <-chan BytesResult {
	return c.cryptFile(inputPath, outputPath, c.encryptChunk)
}

func (c *Context) DecryptFile(inputPath, outputPath string) <-chan BytesResult {
	return c.cryptFile(inputPath, outputPath, c.decryptChunk)
}

func (c *Context) cryptFile(inputPath, outputPath string, operation chunkOperation) <-chan BytesResult {
	ch := make(chan BytesResult, 1)
	go func() {
		var result BytesResult
		defer func() {
			ch <- result
			close(ch)
		}()

		input, err := os.Open(inputPath)
		if err != nil {
			result.Err = fmt.Errorf("open input file: %w", err)
			return
		}
		defer func() {
			if err = input.Close(); err != nil {
				result.Err = errors.Join(result.Err, fmt.Errorf("close input file: %w", err))
			}
		}()
		info, err := input.Stat()
		if err != nil {
			result.Err = fmt.Errorf("stat input file: %w", err)
			return
		}
		if !info.Mode().IsRegular() {
			result.Err = fmt.Errorf("input %q is not a regular file", inputPath)
			return
		}

		if outputInfo, err := os.Stat(outputPath); err == nil && os.SameFile(info, outputInfo) {
			result.Err = fmt.Errorf("%w: %q", ErrSameFile, outputPath)
			return
		}

		output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			result.Err = fmt.Errorf("create output file: %w", err)
			return
		}
		defer func() {
			if err = output.Close(); err != nil {
				result.Err = errors.Join(result.Err, fmt.Errorf("close output file: %w", err))
			}
			if result.Err == nil {
				return
			}
			if err = os.Remove(outputPath); err != nil {
				result.Err = errors.Join(result.Err, fmt.Errorf("remove incomplete output file: %w", err))
			}
		}()

		blockSize := c.algorithm.BlockSize()
		buf := make([]byte, fileChunkSize/blockSize*blockSize)
		remaining := info.Size()
		iv := c.iv
		for {
			n, err := io.ReadFull(input, buf[:min(int64(len(buf)), remaining)])
			if err != nil {
				result.Err = fmt.Errorf("read input file: %w", err)
				return
			}
			remaining -= int64(n)
			last := remaining == 0

			var chunk []byte
			chunk, iv, err = operation(buf[:n], iv, last)
			if err != nil {
				result.Err = err
				return
			}
			if _, err := output.Write(chunk); err != nil {
				result.Err = fmt.Errorf("write output file: %w", err)
				return
			}
			if last {
				return
			}
		}
	}()
	return ch
}
