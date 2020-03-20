package bhx

import (
	"bytes"
	"testing"
)

func TestSalsaEncryption(t *testing.T) {
	var key BoxSharedKey
	copy(key[:], Sha256H([]byte("1337")).Bytes())

	nnonce := GetKeyNonce(key)

	input := []byte("Some text blablabla 123213213")
	ciphertext, err := Encrypt(input, key, nnonce)
	if err != nil {
		t.Fatal(err)
	}

	output, err := Decrypt(ciphertext, key, nnonce)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(input, output) {
		t.Fatalf("cannot decrypt data, want %s got %s", input, output)
	}
}
