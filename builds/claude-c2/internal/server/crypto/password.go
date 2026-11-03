package crypto

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Hasher hashes and verifies passwords with argon2id, limiting concurrency.
type Hasher struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	sem       chan struct{}
	dummy     string
}

// NewHasher returns a Hasher with t=2, p=2 and the given memory, allowing at
// most 4 concurrent hash computations.
func NewHasher(memoryKiB uint32) *Hasher {
	h := &Hasher{MemoryKiB: memoryKiB, Time: 2, Threads: 2, sem: make(chan struct{}, 4)}
	// A fixed dummy hash with the live parameters, used for unknown emails so
	// that login timing is similar for unknown and known accounts.
	h.dummy = h.encode(RandomBytes(16), "coffer-dummy-password-never-matches")
	return h
}

func (h *Hasher) encode(salt []byte, password string) string {
	key := argon2.IDKey([]byte(password), salt, h.Time, h.MemoryKiB, h.Threads, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.MemoryKiB, h.Time, h.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-format argon2id hash of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.encode(RandomBytes(16), password), nil
}

// Verify checks password against a PHC hash. Malformed hashes never verify.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (bool, error) {
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	return verifyPHC(encoded, password), nil
}

// Slot acquires one of the limited hashing slots. Callers that must not
// hold other resources (e.g. a DB connection) while queued use Slot first and
// then the *Held variants.
func (h *Hasher) Slot(ctx context.Context) (release func(), err error) {
	if err := h.acquire(ctx); err != nil {
		return nil, err
	}
	return h.release, nil
}

// VerifyHeld verifies without acquiring a slot (the caller holds one).
func (h *Hasher) VerifyHeld(encoded, password string) bool { return verifyPHC(encoded, password) }

// HashHeld hashes without acquiring a slot (the caller holds one).
func (h *Hasher) HashHeld(password string) string { return h.encode(RandomBytes(16), password) }

// DummyHeld burns the cost of one verify without acquiring a slot.
func (h *Hasher) DummyHeld(password string) { verifyPHC(h.dummy, password) }

// VerifyDummy burns the same CPU as a real verify and always returns false.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	_, err := h.Verify(ctx, h.dummy, password)
	return err
}

// NeedsRehash reports whether encoded was made with parameters other than
// h's (or is not a hash h can parse). Verification cost follows the stored
// parameters, so stale hashes would make known accounts measurably slower or
// faster than the unknown-email dummy.
func (h *Hasher) NeedsRehash(encoded string) bool {
	m, t, p, _, key, err := parsePHC(encoded)
	return err != nil || m != h.MemoryKiB || t != h.Time || p != h.Threads || len(key) != 32
}

var errPHC = errors.New("bad phc")

func parsePHC(encoded string) (m, t uint32, p uint8, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errPHC
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return 0, 0, 0, nil, nil, errPHC
	}
	var pp uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &pp); err != nil {
		return 0, 0, 0, nil, nil, errPHC
	}
	if m < 8 || m > 4*1024*1024 || t < 1 || t > 16 || pp < 1 || pp > 16 {
		return 0, 0, 0, nil, nil, errPHC
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return 0, 0, 0, nil, nil, errPHC
	}
	return m, t, uint8(pp), salt, key, nil
}

func verifyPHC(encoded, password string) bool {
	m, t, p, salt, key, err := parsePHC(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}
