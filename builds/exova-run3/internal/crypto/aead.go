package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// newGCM builds the AES-256-GCM AEAD for a key.
func newGCM(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		// Unreachable for a 32-byte key; reported as a size problem rather than wrapped,
		// because the underlying error text is not something a caller can act on.
		return nil, ErrKeySize
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKeySize
	}
	return gcm, nil
}

// Seal encrypts plaintext under k with a fresh random 96-bit nonce and the given associated data.
// It returns the nonce and the ciphertext (which carries the 16-byte tag).
//
// A zero-length plaintext is valid and seals to a tag-only ciphertext, so an empty secret value
// round-trips exactly.
func Seal(k Key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(k)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, ErrRandom
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates ciphertext under k with the given associated data.
//
// Every failure mode — wrong key, truncated ciphertext, wrong nonce length, or associated data
// that does not match what the value was sealed with — returns ErrDecrypt and no plaintext at all.
// A ciphertext copied into another row therefore cannot return a value.
func Open(k Key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrDecrypt
	}
	if len(ciphertext) < TagSize {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
