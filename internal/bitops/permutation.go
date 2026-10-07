package bitops

import "errors"

var (
	ErrInvalidBitOrder = errors.New("invalid bit order")
	ErrInvalidFirstBit = errors.New("first bit number must be 0 or 1")
	ErrInvalidPBlock   = errors.New("invalid P-block")
)

func PermuteBits(value []byte, pBlock []int, order BitOrder, firstBit int) ([]byte, error) {
	if firstBit != 0 && firstBit != 1 {
		return nil, ErrInvalidFirstBit
	}
	if order != LeastSignificantFirst && order != MostSignificantFirst {
		return nil, ErrInvalidBitOrder
	}

	result := make([]byte, (len(pBlock)+7)/8)
	for i, pVal := range pBlock {
		position := pVal - firstBit
		if position < 0 || position >= len(value)*8 {
			return nil, ErrInvalidPBlock
		}
		if bitAt(value, position, order) {
			setBit(result, i, order)
		}
	}
	return result, nil
}
