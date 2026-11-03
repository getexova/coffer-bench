// Package config loads and validates the Coffer server configuration from
// environment variables (CONTRACT §2).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// PlaceholderMasterKey is the value shipped in .env.example. It is rejected.
const PlaceholderMasterKey = "REPLACE_ME_with_output_of_init_env_sh_0000000000="

// MinArgon2MemoryKiB is the lowest accepted argon2id memory parameter.
const MinArgon2MemoryKiB = 19456

// Config is the validated server configuration.
type Config struct {
	MasterKey         []byte
	PreviousMasterKey []byte // nil unless rotating

	BootstrapEmail    string
	BootstrapPassword string

	ListenAddr  string
	DatabaseURL string // owner DSN

	TrustProxy            bool
	PATTTL                time.Duration
	Argon2MemoryKiB       uint32
	RequirePasswordChange bool

	// AppRole is the restricted database role used by the request pool (P1).
	// Not configurable through the environment; tests override it so parallel
	// test databases on one cluster do not fight over a shared role password.
	AppRole string
}

// Error is a configuration error. Its message is printed as "config error: ...".
type Error struct{ Msg string }

func (e *Error) Error() string { return "config error: " + e.Msg }

func missing(name string) error {
	return &Error{Msg: "missing required environment variable " + name}
}

func invalid(name, why string) error {
	return &Error{Msg: "invalid environment variable " + name + ": " + why}
}

// Load reads the configuration using lookup (normally os.LookupEnv).
func Load(lookup func(string) (string, bool)) (*Config, error) {
	get := func(name string) string {
		v, ok := lookup(name)
		if !ok {
			return ""
		}
		return strings.TrimSpace(v)
	}

	// 1. Required variables, checked for presence first so the message names
	// the first missing one.
	dbURL := get("COFFER_DATABASE_URL")
	required := []string{"COFFER_MASTER_KEY", "COFFER_BOOTSTRAP_ADMIN_EMAIL", "COFFER_BOOTSTRAP_ADMIN_PASSWORD"}
	if dbURL == "" {
		required = append(required, "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB")
	}
	for _, name := range required {
		if get(name) == "" {
			return nil, missing(name)
		}
	}

	c := &Config{AppRole: "coffer_app"}

	// 2. Master keys.
	mk, err := ParseMasterKey(get("COFFER_MASTER_KEY"))
	if err != nil {
		return nil, invalid("COFFER_MASTER_KEY", err.Error())
	}
	c.MasterKey = mk
	if prev := get("COFFER_MASTER_KEY_PREVIOUS"); prev != "" {
		pk, err := ParseMasterKey(prev)
		if err != nil {
			return nil, invalid("COFFER_MASTER_KEY_PREVIOUS", err.Error())
		}
		c.PreviousMasterKey = pk
	}

	// 3. Bootstrap admin.
	c.BootstrapEmail = get("COFFER_BOOTSTRAP_ADMIN_EMAIL")
	if _, ok := NormalizeEmail(c.BootstrapEmail); !ok {
		return nil, invalid("COFFER_BOOTSTRAP_ADMIN_EMAIL", "not a valid email address")
	}
	// The password is used verbatim (not trimmed).
	c.BootstrapPassword, _ = lookup("COFFER_BOOTSTRAP_ADMIN_PASSWORD")
	if err := CheckPassword(c.BootstrapPassword); err != nil {
		return nil, invalid("COFFER_BOOTSTRAP_ADMIN_PASSWORD", err.Error())
	}

	// 4. Network / database.
	c.ListenAddr = get("COFFER_LISTEN_ADDR")
	if c.ListenAddr == "" {
		c.ListenAddr = ":8420"
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return nil, invalid("COFFER_LISTEN_ADDR", "must be host:port")
	}
	if dbURL != "" {
		c.DatabaseURL = dbURL
	} else {
		host := get("POSTGRES_HOST")
		if host == "" {
			host = "db"
		}
		port := get("POSTGRES_PORT")
		if port == "" {
			port = "5432"
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return nil, invalid("POSTGRES_PORT", "must be a port number")
		}
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(get("POSTGRES_USER"), get("POSTGRES_PASSWORD")),
			Host:     net.JoinHostPort(host, port),
			Path:     "/" + get("POSTGRES_DB"),
			RawQuery: "sslmode=disable",
		}
		if v := get("POSTGRES_SSLMODE"); v != "" {
			u.RawQuery = "sslmode=" + url.QueryEscape(v)
		}
		c.DatabaseURL = u.String()
	}

	// 5. Optional knobs.
	switch strings.ToLower(get("COFFER_TRUST_PROXY")) {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		c.TrustProxy = true
	default:
		return nil, invalid("COFFER_TRUST_PROXY", "must be true or false")
	}
	c.PATTTL = 720 * time.Hour
	if v := get("COFFER_PAT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 8760*time.Hour {
			return nil, invalid("COFFER_PAT_TTL", "must be a duration between 1m and 8760h")
		}
		c.PATTTL = d
	}
	c.Argon2MemoryKiB = 65536
	if v := get("COFFER_ARGON2_MEMORY_KIB"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < MinArgon2MemoryKiB || n > 4*1024*1024 {
			return nil, invalid("COFFER_ARGON2_MEMORY_KIB", fmt.Sprintf("must be an integer between %d and %d", MinArgon2MemoryKiB, 4*1024*1024))
		}
		c.Argon2MemoryKiB = uint32(n)
	}
	switch strings.ToLower(get("COFFER_REQUIRE_PASSWORD_CHANGE")) {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		c.RequirePasswordChange = true
	default:
		return nil, invalid("COFFER_REQUIRE_PASSWORD_CHANGE", "must be true or false")
	}
	return c, nil
}

// FromEnv loads the configuration from the process environment.
func FromEnv() (*Config, error) { return Load(os.LookupEnv) }

// ParseMasterKey decodes a base64 master key (std/raw/url variants) and
// rejects the placeholder and anything that is not exactly 32 bytes.
func ParseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == PlaceholderMasterKey {
		return nil, errors.New("is the .env.example placeholder; run ./scripts/init-env.sh")
	}
	var key []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.Strict().DecodeString(s); err == nil {
			key = b
			break
		}
	}
	if key == nil {
		return nil, errors.New("is not valid base64")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("must decode to exactly 32 bytes (got %d)", len(key))
	}
	return key, nil
}

// CheckPassword enforces the password policy: valid UTF-8, at least 12
// characters (runes), at most 1024 bytes, no NUL.
func CheckPassword(p string) error {
	if !utf8.ValidString(p) {
		return errors.New("password must be valid UTF-8")
	}
	if strings.IndexByte(p, 0) >= 0 {
		return errors.New("password must not contain NUL")
	}
	if utf8.RuneCountInString(p) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(p) > 1024 {
		return errors.New("password must be at most 1024 bytes")
	}
	return nil
}

// NormalizeEmail returns lower(trim(email)) and whether it looks like an
// email address (one '@', non-empty local and domain parts, ≤ 254 bytes, no
// whitespace or control characters).
func NormalizeEmail(email string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(email))
	if n == "" || len(n) > 254 || !utf8.ValidString(n) {
		return n, false
	}
	at := strings.IndexByte(n, '@')
	if at <= 0 || at != strings.LastIndexByte(n, '@') || at == len(n)-1 {
		return n, false
	}
	for _, r := range n {
		if r <= 0x20 || r == 0x7f || r == '<' || r == '>' || r == '"' || r == '\\' || r == ',' || r == ';' {
			return n, false
		}
	}
	return n, true
}
