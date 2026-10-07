package paddings

import (
	"crypto/rand"
)

func padISO10126(data []byte, blockSize int) []byte {
	length := paddingLength(data, blockSize)
	result := append(data, make([]byte, length)...)
	_, _ = rand.Read(result[len(data) : len(result)-1])
	result[len(result)-1] = byte(length)
	return result
}

func unpadISO10126(data []byte, blockSize int) ([]byte, error) {
	length, err := readPaddingLength(data, blockSize)
	if err != nil {
		return nil, err
	}
	return data[:len(data)-length], nil
}
