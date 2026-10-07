package modes

import "github.com/ariollex/crypto/internal/bitops"

func (r *runner) cryptCTR(data []byte) ([]byte, error) {
	one := make([]byte, r.blockSize())
	one[len(one)/2-1] = 1
	return r.cryptCounter(data, r.iv, one)
}

func (r *runner) cryptCounter(data, i, delta []byte) ([]byte, error) {
	blockSize := r.blockSize()
	counter := i
	for start := 0; start < len(data); start += blockSize {
		keyStream, err := r.encryptBlock(counter)
		if err != nil {
			return nil, err
		}
		_ = bitops.XOR(data[start:start+blockSize], keyStream)
		counter = bitops.ModAdd(counter, delta)
	}
	r.iv = counter
	return data, nil
}
