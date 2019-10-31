package bhx

import (
	"crypto/rand"
	"encoding/binary"
)

var le = binary.LittleEndian

// Uint64Le is alias for binary.LittleEndian.Uint64
func Uint64Le(b []byte) uint64 { return le.Uint64(b) }

// Uint32Le is alias for binary.LittleEndian.Uint32
func Uint32Le(b []byte) uint32 { return le.Uint32(b) }

// Uint16Le is alias for binary.LittleEndian.Uint16
func Uint16Le(b []byte) uint16 { return le.Uint16(b) }

// PutUint64Le is alias for binary.LittleEndian.PutUint64
func PutUint64Le(b []byte, v uint64) { le.PutUint64(b, v) }

// PutUint32Le is alias for binary.LittleEndian.PutUint32
func PutUint32Le(b []byte, v uint32) { le.PutUint32(b, v) }

// PutUint16Le is alias for binary.LittleEndian.PutUint16
func PutUint16Le(b []byte, v uint16) { le.PutUint16(b, v) }

// RandUint64 returns random uint64 value
func RandUint64() uint64 {
	b := make([]byte, 8)
	rand.Read(b)
	return Uint64Le(b)
}
