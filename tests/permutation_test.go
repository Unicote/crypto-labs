package tests

import (
	"bytes"
	"testing"

	"github.com/ariollex/crypto/internal/bitops"
)

func TestPermuteBits(t *testing.T) {
	input := []byte{0b_0001_0010, 0b_1011_0000, 0, 0, 0, 0, 0, 0}

	tests := []struct {
		name     string
		pBlock   []int
		order    bitops.BitOrder
		firstBit int
		want     []byte
	}{
		{
			name:     "LSF",
			pBlock:   []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0},
			order:    bitops.LeastSignificantFirst,
			firstBit: 0,
			want:     []byte{0b_0000_1001, 0b_0101_1000, 0, 0, 0, 0, 0, 0},
		},
		{
			name:     "MSF",
			pBlock:   []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 1},
			order:    bitops.MostSignificantFirst,
			firstBit: 1,
			want:     []byte{0b_0010_0101, 0b_0110_0000, 0, 0, 0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bitops.PermuteBits(input, tt.pBlock, tt.order, tt.firstBit)
			if err != nil {
				t.Fatalf("PermuteBits returned an error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("PermuteBits() = % X, want % X", got, tt.want)
			}
		})
	}
}
