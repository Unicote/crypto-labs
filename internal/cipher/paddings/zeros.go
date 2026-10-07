package paddings

import "bytes"

func padZeros(data []byte, blockSize int) []byte {
	length := paddingLength(data, blockSize) % blockSize
	return append(data, bytes.Repeat([]byte{0}, length)...)
}

func unpadZeros(data []byte) ([]byte, error) {
	trimmed := bytes.TrimRight(data, string(byte(0)))
	if len(trimmed) == 0 && len(data) > 0 {
		return []byte{0}, nil
	}
	return trimmed, nil
}
