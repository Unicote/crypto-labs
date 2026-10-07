package paddings

import (
	"bytes"
	"fmt"
)

func padPKCS7(data []byte, blockSize int) []byte {
	length := paddingLength(data, blockSize)
	return append(data, bytes.Repeat([]byte{byte(length)}, length)...)
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	length, err := readPaddingLength(data, blockSize)
	if err != nil {
		return nil, err
	}
	start := len(data) - length
	if bytes.Count(data[start:], []byte{byte(length)}) != length {
		return nil, fmt.Errorf("%w: invalid PKCS7 padding", ErrInvalidPadding)
	}
	return data[:start], nil
}
