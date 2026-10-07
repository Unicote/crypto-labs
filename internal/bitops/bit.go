package bitops

type BitOrder uint8

const (
	LeastSignificantFirst BitOrder = iota
	MostSignificantFirst
)

func bitAddress(position int, order BitOrder) (int, int) {
	index := position % 8
	if order == MostSignificantFirst {
		index = 7 - index
	}
	return position / 8, index
}

func bitAt(value []byte, position int, order BitOrder) bool {
	byteIdx, bitIdx := bitAddress(position, order)
	return (value[byteIdx]>>bitIdx)&1 != 0
}

func setBit(value []byte, position int, order BitOrder) {
	byteIdx, bitIdx := bitAddress(position, order)
	value[byteIdx] |= 1 << bitIdx
}
