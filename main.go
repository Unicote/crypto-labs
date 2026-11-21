package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ariollex/crypto/algorithms/deal"
	"github.com/ariollex/crypto/algorithms/des"
	"github.com/ariollex/crypto/algorithms/rsa"
	"github.com/ariollex/crypto/attacks/wiener"
	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/cipher/modes"
	"github.com/ariollex/crypto/internal/cipher/paddings"
	"github.com/ariollex/crypto/internal/numtheory"
)

const (
	samplesDir   = "tests/testdata"
	encryptedDir = "out/encrypted"
	decryptedDir = "out/decrypted"
	encryptedExt = ".enc"
)

var modeNames = map[string]modes.Mode{
	"ECB": modes.ECB, "CBC": modes.CBC, "PCBC": modes.PCBC, "CFB": modes.CFB,
	"OFB": modes.OFB, "CTR": modes.CTR, "RandomDelta": modes.RandomDelta,
}

type FileCipher interface {
	EncryptFile(input, output string) <-chan cipher.BytesResult
	DecryptFile(input, output string) <-chan cipher.BytesResult
}

type cipherOptions struct {
	encrypt, decrypt                     bool
	wiener, rsaAttack                    bool
	modeName, paddingName, keyHex, ivHex string
	rsaN, rsaD, rsaE                     string
}

var algorithms = map[string]func(cipherOptions) (FileCipher, error){
	"DES": func(options cipherOptions) (FileCipher, error) {
		return newSymmetricFileCipher(des.NewDES(), "0000000000000004", options)
	},
	"DEAL": func(options cipherOptions) (FileCipher, error) {
		return newSymmetricFileCipher(deal.NewDEAL(), "000102030405060708090a0b0c0d0e0f", options)
	},
	"RSA": newRSAFileCipher,
}

var paddingNames = map[string]paddings.Mode{
	"Zeros": paddings.Zeros, "ANSIX923": paddings.ANSIX923, "PKCS7": paddings.PKCS7, "ISO10126": paddings.ISO10126,
}

func main() {
	encrypt := flag.Bool("encrypt", false, "encrypt "+samplesDir+" into "+encryptedDir)
	decrypt := flag.Bool("decrypt", false, "decrypt "+encryptedDir+" into "+decryptedDir)
	wiener := flag.Bool("wiener", false, "generate a small odd d for a demonstration modulus")
	modeName := flag.String("mode", "CBC", "cipher mode: ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta")
	paddingName := flag.String("pad", "PKCS7", "padding: Zeros, ANSIX923, PKCS7, ISO10126")
	algorithmName := flag.String("alg", "DES", "algorithm: DES, DEAL or RSA")
	keyHex := flag.String("key", "", "key in hex (default: DES 0000000000000004, DEAL 000102030405060708090a0b0c0d0e0f; DEAL also takes 24 or 32 bytes)")
	ivHex := flag.String("iv", "", "initialization vector in hex, one block (default: 0123456789abcdef repeated to the block size)")
	rsaN := flag.String("rsa-n", "", "RSA modulus in decimal for -decrypt or -wiener")
	rsaD := flag.String("rsa-d", "", "RSA private exponent in decimal for decryption")
	rsaE := flag.String("rsa-e", "", "RSA public exponent in decimal for encryption")
	rsaAttack := flag.Bool("rsa-attack", false, "RSA wiener attack")
	flag.Parse()

	options := cipherOptions{
		encrypt:  *encrypt,
		decrypt:  *decrypt,
		wiener:   *wiener,
		modeName: *modeName, paddingName: *paddingName,
		keyHex: *keyHex, ivHex: *ivHex,
		rsaN: *rsaN, rsaD: *rsaD,
		rsaE:      *rsaE,
		rsaAttack: *rsaAttack,
	}
	if err := run(*algorithmName, options); err != nil {
		_, err = fmt.Fprintln(os.Stderr, "error:", err)
		if err != nil {
			return
		}
		os.Exit(1)
	}
}

func run(algorithmName string, options cipherOptions) error {
	if options.wiener {
		if options.encrypt || options.decrypt || options.rsaD != "" {
			return fmt.Errorf("-wiener cannot be combined with -encrypt, -decrypt, or -rsa-d")
		}
		return generateSmallExponent(options.rsaN)
	}
	if options.encrypt == options.decrypt {
		return fmt.Errorf("pass one of -encrypt or -decrypt")
	}
	create, ok := algorithms[algorithmName]
	if !ok {
		return fmt.Errorf("unknown algorithm %q", algorithmName)
	}
	service, err := create(options)
	if err != nil {
		return err
	}
	return cryptFiles(options.decrypt, service)
}

func generateSmallExponent(modulus string) error {
	if modulus == "" {
		modulus = "1022117"
	}
	n, ok := new(big.Int).SetString(modulus, 10)
	if !ok || n.Sign() <= 0 {
		return fmt.Errorf("pass a positive decimal modulus with -rsa-n")
	}

	one := big.NewInt(1)
	three := big.NewInt(3)
	factor := big.NewInt(81)
	limit := new(big.Int).Sub(n, one)
	limit.Quo(limit, factor)
	maxD := numtheory.Sqrt(numtheory.Sqrt(limit))
	if maxD.Cmp(three) < 0 {
		return fmt.Errorf("modulus is too small for an odd d >= 3 with 81*d^4 < n")
	}

	count := new(big.Int).Sub(maxD, one)
	count.Rsh(count, 1)
	index, err := rand.Int(rand.Reader, count)
	if err != nil {
		return err
	}
	d := index.Lsh(index, 1).Add(index, three)
	dSquared := new(big.Int).Mul(d, d)
	scaled := new(big.Int).Mul(dSquared, dSquared)
	scaled.Mul(scaled, factor)
	fmt.Printf("n = %s\nd = %s\n81*d^4 = %s < n\n", n, d, scaled)
	return nil
}

func newSymmetricFileCipher(algorithm cipher.SymmetricAlgorithm, defaultKey string, options cipherOptions) (FileCipher, error) {
	keyHex, ivHex := options.keyHex, options.ivHex
	if keyHex == "" {
		keyHex = defaultKey
	}
	if ivHex == "" {
		ivHex = strings.Repeat("0123456789abcdef", algorithm.BlockSize()/8)
	}
	mode, ok := modeNames[options.modeName]
	if !ok {
		return nil, fmt.Errorf("unknown mode %q", options.modeName)
	}
	padding, ok := paddingNames[options.paddingName]
	if !ok {
		return nil, fmt.Errorf("unknown padding %q", options.paddingName)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}
	if mode == modes.ECB {
		iv = nil
	}

	return cipher.NewContext(algorithm, key, mode, padding, iv)
}

func newRSAFileCipher(options cipherOptions) (FileCipher, error) {
	var service *rsa.RSA
	if options.rsaAttack {
		n, ok := new(big.Int).SetString(options.rsaN, 10)
		if !ok || n.Sign() <= 0 || n.BitLen() < 17 {
			return nil, fmt.Errorf("pass a valid decimal RSA modulus with -rsa-n")
		}
		e, ok := new(big.Int).SetString(options.rsaE, 10)
		if !ok || e.Sign() <= 0 || e.BitLen() < 17 {
			return nil, fmt.Errorf("pass a valid decimal RSA modulus with -rsa-n")
		}
		public := rsa.Key{Modulus: n, Exponent: e}
		d, _, _, err := wiener.Attack(public)
		if err != nil {
			return nil, fmt.Errorf(": %w", err)
		}
		service = &rsa.RSA{Private: rsa.Key{Modulus: n, Exponent: d}}
	} else if !options.decrypt {
		if options.rsaN != "" || options.rsaD != "" {
			return nil, fmt.Errorf("-rsa-n and -rsa-d are for decryption")
		}
		var err error
		service, err = rsa.New(rsa.Fermat, 0.99, 512)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Public key: N=%s e=%s\n", service.Public.Modulus, service.Public.Exponent)
		fmt.Printf("Private key: N=%s d=%s\n", service.Private.Modulus, service.Private.Exponent)
		fmt.Printf("Decrypt: go run . -alg RSA -decrypt -rsa-n %s -rsa-d %s\n", service.Private.Modulus, service.Private.Exponent)
	} else {
		n, ok := new(big.Int).SetString(options.rsaN, 10)
		if !ok || n.Sign() <= 0 || n.BitLen() < 17 {
			return nil, fmt.Errorf("pass a valid decimal RSA modulus with -rsa-n")
		}
		d, ok := new(big.Int).SetString(options.rsaD, 10)
		if !ok || d.Cmp(big.NewInt(1)) <= 0 || d.Cmp(n) >= 0 {
			return nil, fmt.Errorf("pass a valid decimal RSA private exponent with -rsa-d")
		}
		service = &rsa.RSA{Private: rsa.Key{Modulus: n, Exponent: d}}
	}
	return service, nil
}

func cryptFiles(decrypt bool, service FileCipher) error {
	inputDir, outputDir, crypt := samplesDir, encryptedDir, service.EncryptFile
	if decrypt {
		inputDir, outputDir, crypt = encryptedDir, decryptedDir, service.DecryptFile
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return err
	}

	var outputPaths []string
	var results []<-chan cipher.BytesResult
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		outputName := name + encryptedExt
		if decrypt {
			if !strings.HasSuffix(name, encryptedExt) {
				continue
			}
			outputName = strings.TrimSuffix(name, encryptedExt)
		}
		outputPath := filepath.Join(outputDir, outputName)
		outputPaths = append(outputPaths, outputPath)
		results = append(results, crypt(filepath.Join(inputDir, name), outputPath))
	}

	failed := false
	for i, outputPath := range outputPaths {
		if err = (<-results[i]).Err; err != nil {
			fmt.Printf("FAIL %s: %v\n", outputPath, err)
			failed = true
			continue
		}
		fmt.Println("ok  ", outputPath)
	}
	if failed {
		return fmt.Errorf("some files failed")
	}
	return nil
}
