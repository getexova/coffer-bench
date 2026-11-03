// Package crypto implements Coffer's envelope encryption.
//
// A single master key (COFFER_MASTER_KEY, base64 of exactly 32 bytes) wraps one data key per
// project. Data keys encrypt secret values with AES-256-GCM. Every ciphertext is bound to its
// location through associated data built by AAD, so a ciphertext copied into another row fails the
// GCM tag check and returns an error rather than a value.
//
// No function in this package puts plaintext, ciphertext or key material into an error message, and
// Key redacts itself when printed, so a stray %v of a key cannot leak one to a log.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const (
	// KeySize is the AES-256 key length in bytes. COFFER_MASTER_KEY must decode to exactly this.
	KeySize = 32
	// NonceSize is the GCM nonce length in bytes: 96 bits, the size GCM is specified for.
	NonceSize = 12
	// TagSize is the GCM authentication tag length in bytes.
	TagSize = 16
)

// Sentinel errors. They never carry plaintext, ciphertext or key material.
var (
	// ErrKeyMissing is returned when the master key string is empty.
	ErrKeyMissing = errors.New("crypto: master key is not set")
	// ErrKeyFormat is returned when the master key is not valid base64.
	ErrKeyFormat = errors.New("crypto: master key must be base64")
	// ErrKeySize is returned when a key is not exactly 32 bytes.
	ErrKeySize = errors.New("crypto: key must be exactly 32 bytes")
	// ErrDecrypt is returned for every authentication failure: a wrong key, a tampered
	// ciphertext, or associated data that does not match the one it was sealed with.
	ErrDecrypt = errors.New("crypto: decryption failed")
	// ErrRandom is returned when the system random source fails.
	ErrRandom = errors.New("crypto: random source failed")
)

// Key is an AES-256 key: the master key, or a project data key.
//
// It is an array so it is copied by value and can be compared, and it implements String and
// GoString so that printing it (including through a struct) never reveals the key bytes.
type Key [KeySize]byte

// String implements fmt.Stringer, redacting the key.
func (k Key) String() string { return "crypto.Key(redacted)" }

// GoString implements fmt.GoStringer, redacting the key under %#v.
func (k Key) GoString() string { return "crypto.Key(redacted)" }

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// ParseKey decodes a base64 key. It accepts the padded standard encoding that
// `openssl rand -base64 32` produces and, defensively, the unpadded form. Surrounding whitespace
// (for example the trailing newline of a file or a heredoc) is ignored.
//
// A key that is not exactly 32 bytes is refused: an AES-128 or AES-192 key would still "work", and
// silently accepting one would be a downgrade.
func ParseKey(s string) (Key, error) {
	var k Key
	s = strings.TrimSpace(s)
	if s == "" {
		return k, ErrKeyMissing
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return k, ErrKeyFormat
		}
	}
	if len(raw) != KeySize {
		zero(raw)
		return k, ErrKeySize
	}
	copy(k[:], raw)
	zero(raw)
	return k, nil
}

// NewKey returns a fresh random 32-byte key from the system random source.
func NewKey() (Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return Key{}, ErrRandom
	}
	return k, nil
}

// zero overwrites a byte slice with zeroes.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
