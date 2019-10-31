package bhx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

// Hash256 is 32-byte hash value
type Hash256 [32]byte

// EmptyHash256 returns zero hash
func EmptyHash256() Hash256 { return Hash256{} }

// SetBytes copy given byte slice to hash value
func (h *Hash256) SetBytes(b []byte) {
	copy(h[:], b[:])
}

// Bytes convert hash result to byte slice
func (h Hash256) Bytes() []byte {
	return h[:]
}

func (h Hash256) String() string {
	return fmt.Sprintf("0x%s", hex.EncodeToString(h.Bytes()))
}

// Equal returns true, if hashes is equal
func (h Hash256) Equal(h2 Hash256) bool {
	return bytes.Equal(h[:], h2[:])
}

// Empty returns if hash is zero
func (h Hash256) Empty() bool { return h.Equal(Hash256{}) }

// Xor operations for hashes
func (h Hash256) Xor(other Hash256) (ret Hash256) {
	for i := 0; i < 32; i++ {
		ret[i] = h[i] ^ other[i]
	}
	return ret
}

// PrefixLen Возвращает длину префикса ID в сравнении с other
func (h Hash256) PrefixLen(other Hash256) int {
	distance := h.Xor(other)
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			if (distance[i]>>uint8(7-j))&0x1 != 0 {
				return 8*i + j
			}
		}
	}
	return -1
}

// Distance is scalar XOR for hashes
func (h Hash256) Distance(other Hash256) int {
	dist := 0
	for i := 0; i < 32; i++ {
		dist += int(h[i] ^ other[i])
	}
	return dist
}

// ToBigInt returns big.Int from given hash
func (h Hash256) ToBigInt() *big.Int {
	return new(big.Int).SetBytes(h[:])
}

// SetBigInt set big.Int as hash
func (h Hash256) SetBigInt(i *big.Int) Hash256 {
	buf := make([]byte, 32)
	copy(buf, i.Bytes())
	copy(h[:], buf)
	return h
}

// FileSha256 returns SHA3-256 hash of given file
func FileSha256(path string) (fh Hash256, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return
	}

	defer fd.Close()

	h := sha3.New256()
	_, err = io.Copy(h, fd)
	if err != nil {
		return
	}

	copy(fh[:], h.Sum(nil))
	return
}

// Sha256H calculate SHA3-256 hash and returns it as Hash256
func Sha256H(input ...[]byte) Hash256 {
	h := Hash256{}
	// h.SetBytes(utils.SHA256(input...))
	hsr := sha3.New256()
	for i := range input {
		hsr.Write(input[i])
	}

	copy(h[:], hsr.Sum(nil))
	return h
}
