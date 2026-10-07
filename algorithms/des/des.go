package des

import (
	"errors"
	"fmt"

	"github.com/ariollex/crypto/internal/bitops"
	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/feistel"
)

const (
	desBlockSize    = 8
	desKeySize      = 8
	desRoundKeySize = 6
	desRounds       = 16
	desKeyHalfBits  = 28
)

var (
	ErrInvalidKeySize      = errors.New("invalid DES key size")
	ErrInvalidRoundKeySize = errors.New("invalid DES round key size")
)

// region Tables

var initialPermutation = []int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var finalPermutation = []int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

var expansionTable = []int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var roundPermutation = []int{
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
}

var permutedChoice1 = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var permutedChoice2 = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var keyShifts = [desRounds]int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var sBoxes = [8][64]byte{
	{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	},
	{
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
	},
	{
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
	},
	{
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
	},
	{
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
	},
	{
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
	},
	{
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
	},
	{
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
	},
}

// endregion Tables

// region Key Rotation

func rotateHalvesTable(shift int) []int {
	table := make([]int, 0, 2*desKeyHalfBits)
	for half := range 2 {
		for index := range desKeyHalfBits {
			table = append(table, half*desKeyHalfBits+(index+shift)%desKeyHalfBits+1)
		}
	}
	return table
}

var keyRotations = [][]int{nil, rotateHalvesTable(1), rotateHalvesTable(2)}

// endregion Key Rotation

// region Key Expansion

type KeyExpander struct{}

func (KeyExpander) ExpandKey(key cipher.RoundKey) ([]cipher.RoundKey, error) {
	if len(key) != desKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKeySize, len(key), desKeySize)
	}

	halves, err := bitops.PermuteBits(key, permutedChoice1, bitops.MostSignificantFirst, 1)
	if err != nil {
		return nil, err
	}
	roundKeys := make([]cipher.RoundKey, desRounds)
	for round, shift := range keyShifts {
		halves, err = bitops.PermuteBits(halves, keyRotations[shift], bitops.MostSignificantFirst, 1)
		if err != nil {
			return nil, err
		}
		roundKeys[round], err = bitops.PermuteBits(halves, permutedChoice2, bitops.MostSignificantFirst, 1)
		if err != nil {
			return nil, err
		}
	}
	return roundKeys, nil
}

// endregion Key Expansion

// region Round Function

type RoundTransformer struct{}

func (RoundTransformer) Transform(block []byte, roundKey cipher.RoundKey) ([]byte, error) {
	if len(roundKey) != desRoundKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidRoundKeySize, len(roundKey), desRoundKeySize)
	}

	expanded, err := bitops.PermuteBits(block, expansionTable, bitops.MostSignificantFirst, 1)
	if err != nil {
		return nil, err
	}
	_ = bitops.XOR(expanded, roundKey)
	return bitops.PermuteBits(substitute(expanded), roundPermutation, bitops.MostSignificantFirst, 1)
}

func substitute(value []byte) []byte {
	var bits uint64
	for _, b := range value {
		bits = bits<<8 | uint64(b)
	}

	s := func(bits uint64, box int) byte {
		group := bits >> (42 - 6*box) & 0b_11_1111
		row := group>>4&0b_10 | group&0b_01 // b6 | b0
		column := group >> 1 & 0b_1111      // b4...b1
		return sBoxes[box][row*16+column]
	}

	result := make([]byte, 4)
	for i := range result {
		result[i] = s(bits, 2*i)<<4 | s(bits, 2*i+1)
	}
	return result
}

// endregion Round Function

// region DES

type DES struct {
	*feistel.Network
}

func NewDES() *DES {
	network, err := feistel.NewFeistelNetwork(KeyExpander{}, RoundTransformer{}, desBlockSize)
	if err != nil {
		panic(err)
	}
	return &DES{network}
}

func (d *DES) EncryptBlock(block []byte) ([]byte, error) {
	return d.crypt(block, d.Network.EncryptBlock)
}

func (d *DES) DecryptBlock(block []byte) ([]byte, error) {
	return d.crypt(block, d.Network.DecryptBlock)
}

func (d *DES) crypt(block []byte, op func([]byte) ([]byte, error)) ([]byte, error) {
	if len(block) != desBlockSize {
		return nil, fmt.Errorf("%w: block has %d bytes, want %d", cipher.ErrInvalidBlockSize, len(block), desBlockSize)
	}
	block, err := bitops.PermuteBits(block, initialPermutation, bitops.MostSignificantFirst, 1)
	if err != nil {
		return nil, err
	}
	output, err := op(block)
	if err != nil {
		return nil, err
	}
	return bitops.PermuteBits(output, finalPermutation, bitops.MostSignificantFirst, 1)
}

// endregion DES
