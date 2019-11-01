package bhx

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// Box constants
const (
	BoxPubKeyLen    = 32
	BoxPrivKeyLen   = 32
	BoxSharedKeyLen = 32
	BoxNonceLen     = 24
	BoxOverhead     = box.Overhead
)

// BoxPub is NaCl box public key
type BoxPub [BoxPubKeyLen]byte

// BoxPriv is NaCl box private key
type BoxPriv [BoxPrivKeyLen]byte

// BoxSharedKey is NaCl box shared key
type BoxSharedKey [BoxSharedKeyLen]byte

// BoxNonce is NaCl box nonce
type BoxNonce [BoxNonceLen]byte

// GenerateBoxKeys returns NaCl keypair
func GenerateBoxKeys() (*BoxPub, *BoxPriv, error) {
	var (
		bPub  BoxPub
		bPriv BoxPriv
	)

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	copy(bPub[:], pub[:])
	copy(bPriv[:], priv[:])
	return &bPub, &bPriv, nil
}

// GenerateNonce returns new NaCl box nonce
func GenerateNonce() *BoxNonce {
	var nonce BoxNonce
	io.ReadFull(rand.Reader, nonce[:])
	return &nonce
}

// GetSharedKey returns NaCl shared key
func GetSharedKey(sPub *BoxPub, rPriv *BoxPriv) *BoxSharedKey {
	var key, pub, priv [32]byte
	copy(pub[:], sPub[:])
	copy(priv[:], rPriv[:])
	box.Precompute(&key, &pub, &priv)
	var sk BoxSharedKey
	copy(sk[:], key[:])
	return &sk
}

// BoxSeal encrypt message with NaCl shared key
func BoxSeal(nonce *BoxNonce, key *BoxSharedKey, msg []byte) []byte {
	var (
		n [24]byte
		k [32]byte
	)
	copy(n[:], nonce[:])
	copy(k[:], key[:])
	return box.SealAfterPrecomputation(nonce[:], msg, &n, &k)
}

// BoxOpen decrypt message with NaCl shared key
func BoxOpen(msg []byte, key *BoxSharedKey) ([]byte, bool) {
	if len(msg) < 24 {
		return nil, false
	}

	var (
		n [24]byte
		k [32]byte
	)

	copy(n[:], msg[:24])
	copy(k[:], key[:])
	return box.OpenAfterPrecomputation(nil, msg[24:], &n, &k)
}
