package modes

import (
	"bytes"
	"slices"

	"github.com/ariollex/crypto/internal/bitops"
)

func (r *runner) encryptCFB(data []byte) ([]byte, error) {
	cPrev := bytes.Clone(r.iv)
	blockSize := r.blockSize()
	for start := 0; start < len(data); start += blockSize {
		mCur := data[start : start+blockSize]
		cCur, err := r.encryptBlock(cPrev)
		if err != nil {
			return nil, err
		}
		_ = bitops.XOR(mCur, cCur)
		copy(cPrev, mCur)
	}
	r.iv = cPrev
	return data, nil
}

func (r *runner) decryptCFB(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	blockSize := r.blockSize()
	result, err := r.transformBlocks(slices.Concat(r.iv, data[:len(data)-blockSize]), r.encryptBlock)
	if err != nil {
		return nil, err
	}
	r.iv = bytes.Clone(data[len(data)-blockSize:])
	_ = bitops.XOR(data, result)
	return data, nil
}
