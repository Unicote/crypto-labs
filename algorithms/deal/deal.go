package deal

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/ariollex/crypto/algorithms/des"
	"github.com/ariollex/crypto/internal/bitops"
	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/feistel"
)

const (
	dealBlockSize = 16
	desBlockSize  = 8
)

var ErrInvalidKeySize = errors.New("invalid DEAL key size")

// region Key Expansion

var scheduleKey = cipher.RoundKey{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}

type KeyExpander struct{}

func (KeyExpander) ExpandKey(key cipher.RoundKey) ([]cipher.RoundKey, error) {
	var rounds int
	switch len(key) {
	case 16, 24:
		rounds = 6
	case 32:
		rounds = 8
	default:
		return nil, fmt.Errorf("%w: got %d bytes, want 16, 24 or 32", ErrInvalidKeySize, len(key))
	}

	scheduler := des.NewDES()
	if err := scheduler.SetRoundKeys(scheduleKey); err != nil {
		return nil, err
	}
	parts := len(key) / desBlockSize
	roundKeys := make([]cipher.RoundKey, rounds)
	previous := make([]byte, desBlockSize) // RK0 = 0
	for round := range rounds {
		part := round % parts
		block := bytes.Clone(key[part*desBlockSize : (part+1)*desBlockSize])
		constant := make([]byte, desBlockSize)
		if round >= parts {
			constant[desBlockSize-1] = 1 << (round - parts)
		}
		_ = bitops.XOR(block, previous, constant)
		roundKey, err := scheduler.EncryptBlock(block)
		if err != nil {
			return nil, err
		}
		roundKeys[round] = roundKey
		previous = roundKey
	}
	return roundKeys, nil
}

// endregion Key Expansion

// region DES Adapter

type DESAdapter struct {
	ciphers sync.Map
}

func (a *DESAdapter) Transform(block []byte, roundKey cipher.RoundKey) ([]byte, error) {
	algorithm, ok := a.ciphers.Load(string(roundKey))
	if !ok {
		keyed := des.NewDES()
		if err := keyed.SetRoundKeys(roundKey); err != nil {
			return nil, err
		}
		algorithm, _ = a.ciphers.LoadOrStore(string(roundKey), keyed)
	}
	return algorithm.(*des.DES).EncryptBlock(block)
}

// endregion DES Adapter

func NewDEAL() *feistel.Network {
	network, err := feistel.NewFeistelNetwork(KeyExpander{}, &DESAdapter{}, dealBlockSize)
	if err != nil {
		panic(err)
	}
	return network
}
