package cipher

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const fileChunkSize = 64 * 1024

func (c *Context) EncryptFile(inputPath, outputPath string) <-chan BytesResult {
	return c.cryptFile(inputPath, outputPath, c.encryptChunk)
}

func (c *Context) DecryptFile(inputPath, outputPath string) <-chan BytesResult {
	return c.cryptFile(inputPath, outputPath, c.decryptChunk)
}

func (c *Context) cryptFile(inputPath, outputPath string, operation chunkOperation) <-chan BytesResult {
	return TransformFile(inputPath, outputPath, func(input io.Reader, output io.Writer, size int64) error {
		blockSize := c.algorithm.BlockSize()
		buf := make([]byte, fileChunkSize/blockSize*blockSize)
		iv := c.iv
		return TransformChunks(input, output, size, buf, func(chunk []byte, last bool) ([]byte, error) {
			transformed, nextIV, err := operation(chunk, iv, last)
			iv = nextIV
			return transformed, err
		})
	})
}

// TransformChunks transforms a file of the given size using a reusable buffer.
// It calls operation once with an empty final chunk for an empty file.
func TransformChunks(input io.Reader, output io.Writer, size int64, buffer []byte, operation func([]byte, bool) ([]byte, error)) error {
	if len(buffer) == 0 {
		return fmt.Errorf("input chunk size must be positive")
	}
	remaining := size
	for {
		chunk := buffer[:min(int64(len(buffer)), remaining)]
		if _, err := io.ReadFull(input, chunk); err != nil {
			return fmt.Errorf("read input file: %w", err)
		}
		remaining -= int64(len(chunk))
		last := remaining == 0

		transformed, err := operation(chunk, last)
		if err != nil {
			return err
		}
		written, err := output.Write(transformed)
		if err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		if written != len(transformed) {
			return io.ErrShortWrite
		}
		if last {
			return nil
		}
	}
}

func TransformFile(inputPath, outputPath string, operation func(io.Reader, io.Writer, int64) error) <-chan BytesResult {
	result := make(chan BytesResult, 1)
	go func() {
		defer close(result)
		result <- BytesResult{Err: transformFile(inputPath, outputPath, operation)}
	}()
	return result
}

func transformFile(inputPath, outputPath string, operation func(io.Reader, io.Writer, int64) error) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer input.Close()

	info, err := input.Stat()
	if err != nil {
		return fmt.Errorf("stat input file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("input %q is not a regular file", inputPath)
	}
	if existing, err := os.Stat(outputPath); err == nil && os.SameFile(info, existing) {
		return fmt.Errorf("%w: %q", ErrSameFile, outputPath)
	}

	output, err := os.CreateTemp(filepath.Dir(outputPath), ".cipher-*")
	if err != nil {
		return fmt.Errorf("create temporary output file: %w", err)
	}
	defer os.Remove(output.Name())
	writer := bufio.NewWriter(output)
	err = operation(bufio.NewReaderSize(input, fileChunkSize), writer, info.Size())
	if err == nil {
		err = writer.Flush()
	}
	closeErr := output.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(output.Name(), outputPath)
}
