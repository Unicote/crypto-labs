package modes

import (
	"github.com/ariollex/crypto/internal/bitops"
)

func (r *runner) cryptOFB(data []byte) ([]byte, error) {
	blockSize := r.blockSize()
	o := make([]byte, len(data))
	oCur := r.iv
	for start := 0; start < len(data); start += blockSize {
		var err error
		oCur, err = r.encryptBlock(oCur)
		if err != nil {
			return nil, err
		}
		copy(o[start:], oCur)
	}
	r.iv = oCur

	err := r.runParallel(len(data)/blockSize, func(blockIndex int) error {
		start := blockIndex * blockSize
		return bitops.XOR(data[start:start+blockSize], o[start:start+blockSize])
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}
