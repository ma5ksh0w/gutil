# gutil
My golang utilities package

bhx package contains:
- Hash256 type ([32]byte with some funtions)
- Logf function (alias for fmt.Printf with newline at end, ex. Logf("String: %s", str) is equal to fmt.Printf("String: %s\n", str)
- Ed25519 sign/verify helpers
- Hex converting utilities
- binary.LittleEndian.(Put)Uint... aliases
