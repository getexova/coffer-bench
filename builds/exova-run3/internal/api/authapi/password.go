// Package authapi implements the authentication, tenancy and token routes of
// SPEC §7.2 and the authorization rules of SPEC §2 for them: login, logout,
// password change, /me, platform-admin organization management, members, grants,
// projects, environments and service tokens.
//
// Three properties are load-bearing and are implemented here rather than
// delegated:
//
//   - Authentication resolves in one indexed statement with no cache anywhere
//     (internal/store/auth.ResolveTokenSQL), so revocation is visible on the next
//     request.
//   - Authorization runs before field validation, so a plain member calling a
//     member, grant or token route gets 403 and never a 400 that would describe
//     the payload.
//   - Invisibility is a 404 identical to a genuinely missing resource, because
//     every organization-scoped lookup carries the caller's org id in its SQL
//     predicate.
package authapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password policy (SPEC §4).
const (
	// MinPasswordLen is the minimum number of characters in a password.
	MinPasswordLen = 12
	// MaxPasswordLen bounds the input to the key-derivation function. The request
	// body limit is 1 MiB; hashing a megabyte of password on every login attempt
	// would be a cheap way to burn a CPU, so anything longer is a 400.
	MaxPasswordLen = 4096
)

// argon2id parameters. The stored hash carries its own parameters, so raising
// these later does not invalidate existing hashes: an old hash still verifies
// with the parameters it was written with.
const (
	argonMemoryKiB uint32 = 64 * 1024 // 64 MiB
	argonTime      uint32 = 3
	argonThreads   uint8  = 2
	argonKeyLen    uint32 = 32
	argonSaltLen          = 16
)

// errBadHash means a stored hash is not in the format this package writes. It is
// never sent to a client; it is logged as an internal error.
var errBadHash = errors.New("authapi: unrecognised password hash")

// argonSlots bounds how many argon2id computations run at once. Each one holds
// argonMemoryKiB of memory, so without a bound a burst of login attempts would
// turn into an unbounded allocation. The limit is the machine's parallelism, with
// a floor of two so a single-core host still overlaps hashing with I/O.
var argonSlots = make(chan struct{}, max(2, runtime.NumCPU()))

func withArgonSlot(fn func()) {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	fn()
}

// HashPassword derives an argon2id hash in the standard PHC string form:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 key>
//
// The salt is 16 fresh random bytes per call, so two users with the same password
// do not share a hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authapi: read salt: %w", err)
	}

	var key []byte
	withArgonSlot(func() {
		key = argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	})

	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encoded. The comparison is
// constant time. A malformed stored hash is an error, never a match.
func VerifyPassword(encoded, password string) (bool, error) {
	params, salt, want, err := decodeArgon2(encoded)
	if err != nil {
		return false, err
	}

	var got []byte
	withArgonSlot(func() {
		got = argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))
	})
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// argonParams are the cost parameters read back from a stored hash.
type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeArgon2 parses a PHC argon2id string. The parameters are range-checked
// before use so a corrupted row cannot make verification allocate unbounded
// memory or spin forever.
func decodeArgon2(encoded string) (argonParams, []byte, []byte, error) {
	var p argonParams
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, errBadHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, errBadHash
	}
	if p.memory < 8*1024 || p.memory > 1024*1024 || p.time < 1 || p.time > 64 || p.threads < 1 || p.threads > 64 {
		return p, nil, nil, errBadHash
	}

	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return p, nil, nil, errBadHash
	}
	key, err := enc.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return p, nil, nil, errBadHash
	}
	return p, salt, key, nil
}

// dummyPassword is never a real credential. Its hash is verified against when the
// supplied email is unknown, so that an unknown email costs the same argon2id work
// as a wrong password and the two responses cannot be told apart by timing
// (SPEC §4).
const dummyPassword = "coffer-timing-equaliser-not-a-credential"

// dummyHash is computed once at start-up, not on the first unknown-email login:
// paying the derivation cost lazily would make that first request measurably
// slower than a wrong-password request, which is exactly the signal this exists to
// remove.
var dummyHash = buildDummyHash()

func buildDummyHash() string {
	h, err := HashPassword(dummyPassword)
	if err != nil {
		// Only reachable if the platform entropy source is gone, in which case no
		// password can be hashed and the server must not pretend to serve logins.
		panic("authapi: cannot build the timing-equaliser hash: " + err.Error())
	}
	return h
}

// burnPasswordVerify performs a full argon2id verification against the dummy hash
// and discards the result. It is what the unknown-email path runs instead of
// returning early.
func burnPasswordVerify(password string) {
	_, _ = VerifyPassword(dummyHash, password)
}

// validatePassword enforces SPEC §4's minimum length. Length is counted in
// characters, not bytes, so a 12-character non-ASCII passphrase is accepted.
func validatePassword(password string) error {
	if password == "" {
		return errors.New("password is required")
	}
	if n := len([]rune(password)); n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(password) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	}
	return nil
}
