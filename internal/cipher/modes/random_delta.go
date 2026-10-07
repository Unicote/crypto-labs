package modes

import "slices"

func (r *runner) cryptRD(data []byte) ([]byte, error) {
	blockSize := r.blockSize()
	counter, delta := r.iv, rdDelta(r.iv)
	if len(r.iv) == 2*blockSize {
		counter, delta = r.iv[:blockSize], r.iv[blockSize:]
	}
	result, err := r.cryptCounter(data, counter, delta)
	if err != nil {
		return nil, err
	}
	r.iv = slices.Concat(r.iv, delta)
	return result, nil
}

func rdDelta(iv []byte) []byte {
	half := len(iv) / 2
	delta := make([]byte, len(iv))
	copy(delta[half:], iv[half:])
	return delta
}
