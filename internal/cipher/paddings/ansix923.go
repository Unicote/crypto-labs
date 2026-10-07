package paddings

import (
	"bytes"
	"fmt"
)

func padANSIX923(data []byte, blockSize int) []byte {
	length := paddingLength(data, blockSize)
	data = append(data, make([]byte, length)...)
	data[len(data)-1] = byte(length)
	return data
}

func unpadANSIX923(data []byte, blockSize int) ([]byte, error) {
	length, err := readPaddingLength(data, blockSize)
	if err != nil {
		return nil, err
	}
	start := len(data) - length
	if bytes.Count(data[start:], []byte{0}) != length-1 {
		return nil, fmt.Errorf("%w: invalid ANSI X.923 padding", ErrInvalidPadding)
	}
	return data[:start], nil
}
