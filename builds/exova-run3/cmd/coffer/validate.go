package main

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Slugs match ^[a-z0-9][a-z0-9-]{0,62}$ (SPEC §7.1). Validated locally so a bad
// slug is exit 2 before any network call.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Secret keys match ^[A-Z_][A-Z0-9_]{0,127}$ (SPEC §3).
var keyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Email is validated as loosely as possible on purpose: the server owns the real
// rule, and the CLI rejects only input that cannot be an address at all (empty,
// or whitespace inside). Anything else is forwarded, so a 401/404 from the server
// — not a local exit 2 — is what a caller sees for an unknown address.
var emailPattern = regexp.MustCompile(`^\S+$`)

// Token TTLs: a positive integer with a unit, from 1m to 90d (SPEC §7.1).
var ttlPattern = regexp.MustCompile(`^([0-9]{1,6})([smhd])$`)

const (
	ttlMinSeconds = 60
	ttlMaxSeconds = 90 * 86400
)

var (
	validRoles  = []string{"member", "admin", "owner"}
	validLevels = []string{"viewer", "reader", "writer"}
	validAccess = []string{"read", "read-write"}
	validStatus = []string{"pending", "approved", "rejected", "stale"}
	validFormat = []string{"dotenv", "json"}
)

func validateSlug(kind, slug string) error {
	if slug == "" {
		return usagef("missing %s", kind)
	}
	if !slugPattern.MatchString(slug) {
		return usagef("invalid %s %q: must match ^[a-z0-9][a-z0-9-]{0,62}$", kind, slug)
	}
	return nil
}

func validateSecretKey(key string) error {
	if key == "" {
		return usagef("missing secret key")
	}
	if !keyPattern.MatchString(key) {
		return usagef("invalid secret key %q: must match ^[A-Z_][A-Z0-9_]{0,127}$", key)
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return usagef("missing email")
	}
	if !emailPattern.MatchString(email) {
		return usagef("invalid email %q: must not contain whitespace", email)
	}
	return nil
}

func validateOneOf(kind, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return usagef("invalid %s %q: must be one of %s", kind, value, strings.Join(allowed, ", "))
}

func validateRole(role string) error   { return validateOneOf("role", role, validRoles) }
func validateLevel(level string) error { return validateOneOf("level", level, validLevels) }
func validateAccess(a string) error    { return validateOneOf("access", a, validAccess) }
func validateFormat(f string) error    { return validateOneOf("format", f, validFormat) }
func validateChangeStatus(s string) error {
	return validateOneOf("status", s, validStatus)
}

// parseTTL accepts 1m..90d (30m, 12h, 7d) and returns the value in seconds,
// which is what the API takes.
func parseTTL(spec string) (int64, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, usagef("missing --ttl: use a duration such as 30m, 12h or 7d")
	}
	m := ttlPattern.FindStringSubmatch(spec)
	if m == nil {
		return 0, usagef("invalid --ttl %q: use a duration such as 30m, 12h or 7d", spec)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n <= 0 {
		return 0, usagef("invalid --ttl %q: the number must be greater than zero", spec)
	}
	var unit int64
	switch m[2] {
	case "s":
		unit = 1
	case "m":
		unit = 60
	case "h":
		unit = 3600
	case "d":
		unit = 86400
	}
	seconds := n * unit
	if seconds < ttlMinSeconds || seconds > ttlMaxSeconds {
		return 0, usagef("invalid --ttl %q: must be between 1m and 90d", spec)
	}
	return seconds, nil
}

// validateBaseURL rejects a server URL the CLI could not talk to, before any
// request is attempted. The URL never carries a credential (SPEC §4).
func validateBaseURL(raw string) error {
	if raw == "" {
		return usagef("no server URL: pass --url, set COFFER_URL, or run `coffer login --url URL`")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return usagef("invalid server URL %q: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return usagef("invalid server URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return usagef("invalid server URL %q: missing host", raw)
	}
	if u.User != nil {
		return usagef("invalid server URL %q: credentials are never accepted in the URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return usagef("invalid server URL %q: must not carry a query or fragment", raw)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
