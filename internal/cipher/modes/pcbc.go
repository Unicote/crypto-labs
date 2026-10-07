package modes

import (
	"bytes"

	"github.com/ariollex/crypto/internal/bitops"
)

func (r *runner) encryptPCBC(data []byte) ([]byte, error) {
	cmPrev := r.iv
	blockSize := r.blockSize()
	for start := 0; start < len(data); start += blockSize {
		block := data[start : start+blockSize]
		mCur := bytes.Clone(block)
		_ = bitops.XOR(block, cmPrev)
		cCur, err := r.encryptBlock(block)
		if err != nil {
			return nil, err
		}
		copy(block, cCur)
		_ = bitops.XOR(cCur, mCur)
		cmPrev = cCur
	}
	r.iv = cmPrev
	return data, nil
}

func (r *runner) decryptPCBC(data []byte) ([]byte, error) {
	result, err := r.transformBlocks(data, r.decryptBlock)
	if err != nil {
		return nil, err
	}

	cmPrev := bytes.Clone(r.iv)
	blockSize := r.blockSize()
	for start := 0; start < len(data); start += blockSize {
		mCur := result[start : start+blockSize]
		_ = bitops.XOR(mCur, cmPrev)
		copy(cmPrev, mCur)
		_ = bitops.XOR(cmPrev, data[start:start+blockSize])
	}
	r.iv = cmPrev
	return result, nil
}
