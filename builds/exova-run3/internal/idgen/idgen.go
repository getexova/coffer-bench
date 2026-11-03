// Package idgen produces opaque identifiers and credential secrets.
//
// Ids are 12 random bytes as hex, which is 96 bits: short enough to sit in a URL
// and long enough that a guessed id is not a way to enumerate another tenant.
// Credential secrets are 32 random bytes as hex, which is 256 bits, matching the
// requirement in docs/CONTRACTS.md §8.
//
// Every function reads crypto/rand and panics on failure, because the only
// failure mode is the platform's entropy source being gone. Handing back a
// predictable identifier or a weak token would be far worse than stopping.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// Token prefixes (docs/CONTRACTS.md §8).
const (
	PrefixPAT     = "cof_pat_"
	PrefixService = "cof_st_"
)

const (
	idBytes     = 12
	secretBytes = 32
)

// New returns prefix followed by 12 random bytes as lowercase hex.
func New(prefix string) string {
	return prefix + hex.EncodeToString(random(idBytes))
}

// Secret returns prefix followed by 32 random bytes as lowercase hex. It is used
// for personal access tokens (cof_pat_) and service tokens (cof_st_).
func Secret(prefix string) string {
	return prefix + hex.EncodeToString(random(secretBytes))
}

func random(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("idgen: crypto/rand unavailable: " + err.Error())
	}
	return buf
}
