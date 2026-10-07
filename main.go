package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ariollex/crypto/algorithms/deal"
	"github.com/ariollex/crypto/algorithms/des"
	"github.com/ariollex/crypto/internal/cipher"
	"github.com/ariollex/crypto/internal/cipher/modes"
	"github.com/ariollex/crypto/internal/cipher/paddings"
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

var algorithms = map[string]struct {
	create func() cipher.SymmetricAlgorithm
	key    string
}{
	"DES":  {func() cipher.SymmetricAlgorithm { return des.NewDES() }, "0000000000000004"},
	"DEAL": {func() cipher.SymmetricAlgorithm { return deal.NewDEAL() }, "000102030405060708090a0b0c0d0e0f"},
}

var paddingNames = map[string]paddings.Mode{
	"Zeros": paddings.Zeros, "ANSIX923": paddings.ANSIX923, "PKCS7": paddings.PKCS7, "ISO10126": paddings.ISO10126,
}

func main() {
	encrypt := flag.Bool("encrypt", false, "encrypt "+samplesDir+" into "+encryptedDir)
	decrypt := flag.Bool("decrypt", false, "decrypt "+encryptedDir+" into "+decryptedDir)
	modeName := flag.String("mode", "CBC", "cipher mode: ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta")
	paddingName := flag.String("pad", "PKCS7", "padding: Zeros, ANSIX923, PKCS7, ISO10126")
	algorithmName := flag.String("alg", "DES", "algorithm: DES or DEAL")
	keyHex := flag.String("key", "", "key in hex (default: DES 0000000000000004, DEAL 000102030405060708090a0b0c0d0e0f; DEAL also takes 24 or 32 bytes)")
	ivHex := flag.String("iv", "", "initialization vector in hex, one block (default: 0123456789abcdef repeated to the block size)")
	flag.Parse()

	if err := run(*encrypt, *decrypt, *algorithmName, *modeName, *paddingName, *keyHex, *ivHex); err != nil {
		_, err = fmt.Fprintln(os.Stderr, "error:", err)
		if err != nil {
			return
		}
		os.Exit(1)
	}
}

func run(encrypt, decrypt bool, algorithmName, modeName, paddingName, keyHex, ivHex string) error {
	if encrypt == decrypt {
		return fmt.Errorf("pass one of -encrypt or -decrypt")
	}
	alg, ok := algorithms[algorithmName]
	if !ok {
		return fmt.Errorf("unknown algorithm %q", algorithmName)
	}
	algorithm := alg.create()
	if keyHex == "" {
		keyHex = alg.key
	}
	if ivHex == "" {
		ivHex = strings.Repeat("0123456789abcdef", algorithm.BlockSize()/8)
	}
	mode, ok := modeNames[modeName]
	if !ok {
		return fmt.Errorf("unknown mode %q", modeName)
	}
	padding, ok := paddingNames[paddingName]
	if !ok {
		return fmt.Errorf("unknown padding %q", paddingName)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return fmt.Errorf("iv: %w", err)
	}
	if mode == modes.ECB {
		iv = nil
	}

	context, err := cipher.NewContext(algorithm, key, mode, padding, iv)
	if err != nil {
		return err
	}

	inputDir, outputDir, crypt := samplesDir, encryptedDir, context.EncryptFile
	if decrypt {
		inputDir, outputDir, crypt = encryptedDir, decryptedDir, context.DecryptFile
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
