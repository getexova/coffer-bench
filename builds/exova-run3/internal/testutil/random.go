package testutil

import (
	"crypto/rand"
	"encoding/hex"
)

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("testutil: crypto/rand unavailable: " + err.Error())
	}
	return buf
}

// randomHex returns n random bytes as lowercase hex.
func randomHex(n int) string {
	return hex.EncodeToString(randomBytes(n))
}
