package authapi

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"coffer/internal/reqctx"
)

// slugPattern is SPEC §7.1's slug rule, applied to organization, project and
// environment slugs alike.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Service-token access levels and TTL bounds (SPEC §1, §7.2).
const (
	AccessRead      = "read"
	AccessReadWrite = "read-write"

	// MinTTLSeconds is 1 minute and MaxTTLSeconds is 90 days: a service token
	// always has an expiry, and the bounds are the ones the CLI accepts.
	MinTTLSeconds = 60
	MaxTTLSeconds = 90 * 24 * 60 * 60

	// MaxTokenNameLen bounds the optional human label on a service token.
	MaxTokenNameLen = 200
)

// validateSlug checks a slug against ^[a-z0-9][a-z0-9-]{0,62}$.
func validateSlug(kind, slug string) error {
	if slug == "" {
		return errors.New(kind + " slug is required")
	}
	if !slugPattern.MatchString(slug) {
		return errors.New(kind + " slug must match ^[a-z0-9][a-z0-9-]{0,62}$")
	}
	return nil
}

// validateEmail is a deliberately narrow check: exactly one '@', no whitespace or
// control characters, a non-empty local part and a non-empty domain. It does not
// require a dot in the domain, because a self-hosted deployment may use an
// internal name, and it does not accept a display-name form such as
// `Name <a@b>`: an address here is a login identifier, not a header value.
func validateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	if len(email) > 254 {
		return errors.New("email must be at most 254 characters")
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return errors.New("email must not contain whitespace")
	}
	if strings.Count(email, "@") != 1 {
		return errors.New("email must contain exactly one @")
	}
	local, domain, _ := strings.Cut(email, "@")
	if local == "" || domain == "" {
		return errors.New("email must have a local part and a domain")
	}
	if strings.ContainsAny(email, "\"(),:;<>[]\\") {
		return errors.New("email contains characters that are not allowed")
	}
	return nil
}

// validateRole accepts the three organization roles. platform_admin is never
// assignable through an API request: it is created only by first-boot bootstrap.
func validateRole(role string) error {
	switch role {
	case reqctx.RoleOwner, reqctx.RoleAdmin, reqctx.RoleMember:
		return nil
	default:
		return errors.New("role must be one of owner, admin, member")
	}
}

// validateLevel accepts the three grant levels.
func validateLevel(level string) error {
	switch level {
	case "viewer", "reader", "writer":
		return nil
	default:
		return errors.New("level must be one of viewer, reader, writer")
	}
}

// validateAccess accepts the two service-token access levels.
func validateAccess(access string) error {
	switch access {
	case AccessRead, AccessReadWrite:
		return nil
	default:
		return errors.New("access must be read or read-write")
	}
}

// validateTTL enforces 1 minute to 90 days, in seconds.
func validateTTL(ttl int) error {
	if ttl < MinTTLSeconds || ttl > MaxTTLSeconds {
		return errors.New("ttl_seconds must be between 60 (1 minute) and 7776000 (90 days)")
	}
	return nil
}

// validateTokenName bounds the optional label. An empty name is allowed and is
// stored as NULL.
func validateTokenName(name string) error {
	if len(name) > MaxTokenNameLen {
		return errors.New("name must be at most 200 characters")
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("name must not contain control characters")
	}
	return nil
}

// Token prefixes (docs/CONTRACTS.md §8). Anything else is rejected before it
// reaches the database, so a malformed Authorization header is not a query.
const (
	prefixPAT     = "cof_pat_"
	prefixService = "cof_st_"
)

// tokenSecretHexLen is the length of 32 random bytes rendered as hex, which is
// what idgen.Secret appends. A credential shorter than its prefix plus this cannot
// be one this server minted.
const tokenSecretHexLen = 64

// looksLikeToken reports whether s could be a credential this server issued. It
// keeps the resolution query off the path for obvious junk without leaking which
// prefix was wrong.
func looksLikeToken(s string) bool {
	for _, prefix := range []string{prefixPAT, prefixService} {
		if len(s) == len(prefix)+tokenSecretHexLen && strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// bearerToken extracts the credential from the Authorization header. The value is
// never logged.
func bearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// isPublicRoute reports whether a request is served without a credential. Login is
// the only one: everything else under /api/v1 requires a token.
func isPublicRoute(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.Method == http.MethodPost && r.URL.Path == apiPrefix+"/auth/token"
}

// isMustChangeExempt reports whether a route may be called while the caller still
// has to change their password. The list is exactly two entries: the route that
// clears the flag and the route that ends the session (SPEC §4 P1, P1(a)).
func isMustChangeExempt(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case apiPrefix + "/auth/password", apiPrefix + "/auth/logout":
		return true
	default:
		return false
	}
}
