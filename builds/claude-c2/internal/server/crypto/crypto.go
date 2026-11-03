// Package crypto implements Coffer's envelope encryption, AAD construction,
// token generation/hashing, opaque IDs and argon2id password hashing
// (CONTRACT §4).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

const formatV1 = 0x01

// ErrDecrypt is returned for any authentication/format failure. It never
// carries detail that could help an attacker.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Seal encrypts plaintext with AES-256-GCM under key, binding aad.
// Output: 0x01 || nonce(12) || ciphertext||tag.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+gcm.NonceSize(), 1+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	out[0] = formatV1
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return gcm.Seal(out, out[1:1+gcm.NonceSize()], plaintext, aad), nil
}

// Open decrypts a Seal output. Any failure returns ErrDecrypt.
func Open(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrDecrypt
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	ns := gcm.NonceSize()
	if len(sealed) < 1+ns+gcm.Overhead() || sealed[0] != formatV1 {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, sealed[1:1+ns], sealed[1+ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

// DEKAAD binds a wrapped data key to its org and project.
func DEKAAD(orgID, projectID string) []byte {
	return []byte("coffer/dek/v1|" + orgID + "|" + projectID)
}

// CanaryAAD is the AAD of the master-key canary.
func CanaryAAD() []byte { return []byte("coffer/canary/v1") }

// SecretAAD binds a secret ciphertext to org, project, env, key and version.
func SecretAAD(orgID, projectID, envID, key string, version int) []byte {
	return []byte("coffer/secret/v1|" + orgID + "|" + projectID + "|" + envID + "|" + key + "|" + strconv.Itoa(version))
}

// ChangeAAD binds a pending change value to its change request.
func ChangeAAD(orgID, projectID, envID, key, changeID string) []byte {
	return []byte("coffer/change/v1|" + orgID + "|" + projectID + "|" + envID + "|" + key + "|" + changeID)
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; fail closed.
		panic("crypto/rand: " + err.Error())
	}
	return b
}

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewID returns prefix + "_" + base32(lowercase, unpadded) of 20 random bytes.
func NewID(prefix string) string {
	return prefix + "_" + strings.ToLower(idEncoding.EncodeToString(RandomBytes(20)))
}

// Token prefixes.
const (
	PATPrefix     = "cof_pat_"
	ServicePrefix = "cof_st_"
)

// NewToken returns prefix + base64url(32 random bytes).
func NewToken(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(RandomBytes(32))
}

// TokenHash is SHA-256 of the full token string.
func TokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// WellFormedToken reports whether s has a known prefix and a 43-char
// base64url body (256 bits). Used to reject garbage before touching the DB.
func WellFormedToken(s string) bool {
	var body string
	switch {
	case strings.HasPrefix(s, PATPrefix):
		body = s[len(PATPrefix):]
	case strings.HasPrefix(s, ServicePrefix):
		body = s[len(ServicePrefix):]
	default:
		return false
	}
	if len(body) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(body)
	return err == nil && len(b) == 32
}
