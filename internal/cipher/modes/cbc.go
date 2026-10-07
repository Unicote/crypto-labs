package modes

import (
	"bytes"

	"github.com/ariollex/crypto/internal/bitops"
)

func (r *runner) encryptCBC(data []byte) ([]byte, error) {
	cPrev := r.iv
	blockSize := r.blockSize()
	for start := 0; start < len(data); start += blockSize {
		mCur := data[start : start+blockSize]
		_ = bitops.XOR(mCur, cPrev)
		cCur, err := r.encryptBlock(mCur)
		if err != nil {
			return nil, err
		}
		copy(mCur, cCur)
		cPrev = cCur
	}
	r.iv = bytes.Clone(cPrev)
	return data, nil
}

func (r *runner) decryptCBC(data []byte) ([]byte, error) {
	result, err := r.transformBlocks(data, r.decryptBlock)
	if err != nil {
		return nil, err
	}

	blockSize := r.blockSize()
	cPrev := r.iv
	for start := 0; start < len(data); start += blockSize {
		_ = bitops.XOR(result[start:start+blockSize], cPrev)
		cPrev = data[start : start+blockSize]
	}
	r.iv = bytes.Clone(cPrev)
	return result, nil
}
