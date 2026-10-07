package bitops

func ModAdd(a, b []byte) []byte {
	result := make([]byte, len(a))
	acc := 0
	for j := len(a) - 1; j >= 0; j-- {
		s := int(a[j]) + int(b[j]) + acc
		result[j] = byte(s)
		acc = s >> 8
	}
	return result
}
