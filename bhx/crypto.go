package bhx

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/salsa20"
)

var zeroNonce BoxNonce

// Errors
var (
	ErrInvalidByteLen = errors.New("invalid byte length")
)

// GetSha256Hash returns sha2-256 hash for given data
func GetSha256Hash(input ...[]byte) (h Hash256) {
	sha := sha256.New()
	for _, data := range input {
		sha.Write(data)
	}

	copy(h[:], sha.Sum(nil))
	return
}

// GetKeyNonce returns nonce for given key
func GetKeyNonce(key BoxSharedKey) (nonce BoxNonce) {
	kh := Sha256H(key[:], GetSha256Hash(key[:]).Bytes())
	copy(nonce[:], kh[:BoxNonceLen])
	return
}

// Encrypt given data with salsa20 encryption
// nnonce - nonce for decrypt nonce
func Encrypt(data []byte, key BoxSharedKey, nnonce BoxNonce) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidByteLen
	}

	if nnonce == zeroNonce {
		nnonce = GetKeyNonce(key)
	}

	nonce := GenerateNonce()

	result := make([]byte, len(data)+BoxNonceLen)
	salsa20.XORKeyStream(result[:24], nonce[:], nnonce[:], (*[32]byte)(&key))
	salsa20.XORKeyStream(result[24:], data, nonce[:], (*[32]byte)(&key))
	return result, nil
}

// Decrypt given ciphertext with salsa20
// nnonce - nonce for decrypt nonce
func Decrypt(ciphertext []byte, key BoxSharedKey, nnonce BoxNonce) ([]byte, error) {
	if len(ciphertext) < BoxNonceLen+1 {
		return nil, ErrInvalidByteLen
	}

	if nnonce == zeroNonce {
		nnonce = GetKeyNonce(key)
	}

	result := make([]byte, len(ciphertext)-BoxNonceLen)

	var nonce BoxNonce
	salsa20.XORKeyStream(nonce[:], ciphertext[:BoxNonceLen], nnonce[:], (*[32]byte)(&key))
	salsa20.XORKeyStream(result[:], ciphertext[BoxNonceLen:], nonce[:], (*[32]byte)(&key))
	return result, nil
}
