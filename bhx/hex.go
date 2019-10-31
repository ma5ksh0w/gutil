package bhx

import (
	"encoding/hex"
	"strings"
)

// HexDec decode the hex string (supports 0x prefix)
// if the string is not valid returns nil
func HexDec(str string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(str, "0x"))
	if err != nil {
		return nil
	}

	return b
}

// HexEnc encode given bytes to string (without 0x prefix)
func HexEnc(b []byte) string { return hex.EncodeToString(b) }

// HexEnc0x like HexEnc, but add 0x prefix
func HexEnc0x(b []byte) string { return "0x" + HexEnc(b) }

// DecodeHash256 decode string to Hash256
func DecodeHash256(str string) (h Hash256) {
	copy(h[:], HexDec(str))
	return h
}
