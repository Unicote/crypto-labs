package cipher

import "errors"

var (
	ErrNilAlgorithm     = errors.New("symmetric algorithm is nil")
	ErrInvalidBlockSize = errors.New("invalid block size")
	ErrInvalidIV        = errors.New("invalid initialization vector")
	ErrInvalidWorkers   = errors.New("workers count must be positive")
	ErrSameFile         = errors.New("output file is the input file")
)

type RoundKey []byte

type KeyExpander interface {
	ExpandKey(key RoundKey) ([]RoundKey, error)
}

type RoundTransformer interface {
	Transform(block []byte, roundKey RoundKey) ([]byte, error)
}

type SymmetricAlgorithm interface {
	BlockSize() int
	SetRoundKeys(key RoundKey) error
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}
