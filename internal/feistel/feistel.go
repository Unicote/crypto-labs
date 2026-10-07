package feistel

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ariollex/crypto/internal/bitops"
	"github.com/ariollex/crypto/internal/cipher"
)

var (
	ErrNilKeyExpander      = errors.New("key expander is nil")
	ErrNilRoundTransformer = errors.New("round transformer is nil")
	ErrNoRoundKeys         = errors.New("key expander returned no round keys")
	ErrKeyNotSet           = errors.New("key is not set")
)

type Network struct {
	keyExpander cipher.KeyExpander
	f           cipher.RoundTransformer
	blockSize   int
	roundKeys   []cipher.RoundKey
}

func NewFeistelNetwork(keyExpander cipher.KeyExpander, f cipher.RoundTransformer, blockSize int) (*Network, error) {
	if keyExpander == nil {
		return nil, ErrNilKeyExpander
	}
	if f == nil {
		return nil, ErrNilRoundTransformer
	}
	if blockSize <= 0 || blockSize%2 != 0 {
		return nil, fmt.Errorf("%w: Feistel network requires a positive even block size, got %d", cipher.ErrInvalidBlockSize, blockSize)
	}
	return &Network{keyExpander: keyExpander, f: f, blockSize: blockSize}, nil
}

func (n *Network) BlockSize() int {
	return n.blockSize
}

func (n *Network) SetRoundKeys(key cipher.RoundKey) error {
	roundKeys, err := n.keyExpander.ExpandKey(key)
	if err != nil {
		return err
	}
	if len(roundKeys) == 0 {
		return ErrNoRoundKeys
	}

	n.roundKeys = roundKeys
	return nil
}

func (n *Network) EncryptBlock(block []byte) ([]byte, error) {
	return n.crypt(block, false)
}

func (n *Network) DecryptBlock(block []byte) ([]byte, error) {
	return n.crypt(block, true)
}

func (n *Network) crypt(block []byte, reverse bool) ([]byte, error) {
	if len(n.roundKeys) == 0 {
		return nil, ErrKeyNotSet
	}
	if len(block) != n.blockSize {
		return nil, fmt.Errorf("%w: block has %d bytes, want %d", cipher.ErrInvalidBlockSize, len(block), n.blockSize)
	}

	block = bytes.Clone(block)
	half := n.blockSize / 2
	left := block[:half]
	right := block[half:]
	last := len(n.roundKeys) - 1
	for round := range last {
		if err := n.g(left, right, round, reverse); err != nil {
			return nil, err
		}
		left, right = right, left // T
	}
	if err := n.g(left, right, last, reverse); err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func (n *Network) g(left, right []byte, round int, reverse bool) error {
	roundKey := n.roundKeys[round]
	if reverse {
		roundKey = n.roundKeys[len(n.roundKeys)-1-round]
	}

	transformed, err := n.f.Transform(right, roundKey)
	if err != nil {
		return fmt.Errorf("round %d: %w", round+1, err)
	}
	return bitops.XOR(left, transformed)
}
