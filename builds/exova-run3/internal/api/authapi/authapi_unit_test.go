package authapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These tests need no database and no network. They pin the rules that are pure
// functions of their input, and they are the part of this package that can be
// proven without a Postgres.

func TestPasswordRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if strings.Contains(hash, password) {
		t.Fatal("the hash contains the plaintext password")
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("hash is not argon2id PHC form: %q", hash)
	}

	ok, err := VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the correct password did not verify")
	}

	ok, err = VerifyPassword(hash, password+"x")
	if err != nil {
		t.Fatalf("VerifyPassword(wrong): %v", err)
	}
	if ok {
		t.Fatal("a wrong password verified")
	}
}

func TestPasswordHashIsSalted(t *testing.T) {
	a, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	for _, hash := range []string{
		"",
		"plaintext",
		"$argon2id$v=19$m=65536,t=3,p=2$notbase64$notbase64",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=999999999,t=3,p=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
	} {
		ok, err := VerifyPassword(hash, "anything")
		if err == nil {
			t.Errorf("VerifyPassword(%q) returned no error", hash)
		}
		if ok {
			t.Errorf("VerifyPassword(%q) reported a match", hash)
		}
	}
}

// TestDummyHashEqualisesUnknownEmail is the timing requirement in its testable form:
// the unknown-email path must do the same argon2id work as a wrong password, and it
// must produce no match. A wall-clock assertion would be flaky, so this asserts the
// mechanism instead: the dummy hash is a real hash that verifies like any other.
func TestDummyHashEqualisesUnknownEmail(t *testing.T) {
	if dummyHash == "" {
		t.Fatal("dummyHash is empty: the unknown-email path would return early")
	}
	ok, err := VerifyPassword(dummyHash, dummyPassword)
	if err != nil {
		t.Fatalf("the dummy hash does not parse: %v", err)
	}
	if !ok {
		t.Fatal("the dummy hash does not verify its own password, so it is not doing the work")
	}

	// The burn function must not panic and must reject everything else.
	burnPasswordVerify("some other password")
	ok, err = VerifyPassword(dummyHash, "some other password")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("the dummy hash matched a password it was not built from")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := validatePassword("12345678901"); err == nil {
		t.Error("an 11-character password was accepted")
	}
	if err := validatePassword("123456789012"); err != nil {
		t.Errorf("a 12-character password was rejected: %v", err)
	}
	if err := validatePassword(""); err == nil {
		t.Error("an empty password was accepted")
	}
	if err := validatePassword(strings.Repeat("a", MaxPasswordLen+1)); err == nil {
		t.Error("an over-long password was accepted")
	}
	// Length is counted in characters, not bytes.
	if err := validatePassword(strings.Repeat("é", 12)); err != nil {
		t.Errorf("a 12-character non-ASCII password was rejected: %v", err)
	}
}

func TestValidateSlug(t *testing.T) {
	valid := []string{"a", "dev", "prod-1", "a1-b2", strings.Repeat("a", 63)}
	for _, slug := range valid {
		if err := validateSlug("project", slug); err != nil {
			t.Errorf("validateSlug(%q) rejected a valid slug: %v", slug, err)
		}
	}

	// "trailing-" is VALID: SPEC §7.1 fixes the slug rule as
	// ^[a-z0-9][a-z0-9-]{0,62}$, which permits a trailing hyphen. Rejecting it
	// would be a stricter rule than the frozen one, and the acceptance suite is
	// written against the frozen one.
	if err := validateSlug("project", "trailing-"); err != nil {
		t.Errorf("validateSlug(%q) rejected a slug the frozen pattern allows: %v", "trailing-", err)
	}

	invalid := []string{
		"", "-leading", "Upper", "has space", "under_score", "dot.dot",
		strings.Repeat("a", 64),
	}
	for _, slug := range invalid {
		if err := validateSlug("project", slug); err == nil {
			t.Errorf("validateSlug(%q) accepted an invalid slug", slug)
		}
	}
}

func TestValidateEmailAndRoleAndLevel(t *testing.T) {
	if err := validateEmail("person@example.com"); err != nil {
		t.Errorf("a plain address was rejected: %v", err)
	}
	for _, bad := range []string{"", "no-at-sign", "two@at@signs", "a@", "@b", "has space@b", "a b@c"} {
		if err := validateEmail(bad); err == nil {
			t.Errorf("validateEmail(%q) accepted an invalid address", bad)
		}
	}

	if err := validateRole("owner"); err != nil {
		t.Errorf("owner was rejected: %v", err)
	}
	// platform_admin is never assignable through a request.
	if err := validateRole("platform_admin"); err == nil {
		t.Error("platform_admin was accepted as an assignable role")
	}

	if err := validateLevel("writer"); err != nil {
		t.Errorf("writer was rejected: %v", err)
	}
	if err := validateLevel("owner"); err == nil {
		t.Error("owner was accepted as a grant level")
	}
}

func TestValidateTTL(t *testing.T) {
	if err := validateTTL(MinTTLSeconds - 1); err == nil {
		t.Error("a TTL below one minute was accepted")
	}
	if err := validateTTL(MaxTTLSeconds + 1); err == nil {
		t.Error("a TTL above 90 days was accepted")
	}
	for _, ttl := range []int{MinTTLSeconds, 3600, MaxTTLSeconds} {
		if err := validateTTL(ttl); err != nil {
			t.Errorf("validateTTL(%d) rejected a valid TTL: %v", ttl, err)
		}
	}
}

// TestLockoutIsLiteral pins SPEC §4: five failures inside fifteen minutes lock the
// account, and the lock survives a correct password until the window passes.
func TestLockoutIsLiteral(t *testing.T) {
	l := newLockout()
	now := time.Now()
	const email = "victim@example.com"

	for i := 0; i < lockoutThreshold-1; i++ {
		locked, _ := l.fail(email, now)
		if locked {
			t.Fatalf("locked after %d failures, before the threshold", i+1)
		}
	}
	locked, wait := l.fail(email, now)
	if !locked {
		t.Fatal("not locked after the fifth failure")
	}
	if wait <= 0 || wait > lockoutWindow {
		t.Fatalf("lock wait is %v, expected (0, %v]", wait, lockoutWindow)
	}

	// Still locked part-way through the window, which is the "even with the correct
	// password" case: the handler checks this before verifying anything.
	locked, _ = l.locked(email, now.Add(10*time.Minute))
	if !locked {
		t.Fatal("the lock lifted before the window passed")
	}

	// A different account is unaffected.
	locked, _ = l.locked("someone-else@example.com", now)
	if locked {
		t.Fatal("an unrelated account was locked")
	}

	// Past the window the account is free again.
	locked, _ = l.locked(email, now.Add(lockoutWindow+time.Second))
	if locked {
		t.Fatal("the lock did not lift after the window passed")
	}
}

// TestLockoutIsBounded proves the map cannot grow without limit under a spray of
// invented addresses, which is the reason it is an LRU rather than a map.
func TestLockoutIsBounded(t *testing.T) {
	l := newLockout()
	now := time.Now()
	for i := 0; i < failureWindowCapacity*2; i++ {
		l.fail("spray-"+strings.Repeat("x", i%7)+"-"+string(rune('a'+i%26))+"@example.com", now)
	}
	if got := l.records.order.Len(); got > failureWindowCapacity {
		t.Fatalf("failure history holds %d entries, capacity is %d", got, failureWindowCapacity)
	}
}

func TestThrottleRefusesPastBurst(t *testing.T) {
	th := newThrottle(64, 3, 1)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !th.allow("1.2.3.4", now) {
			t.Fatalf("attempt %d was refused inside the burst", i+1)
		}
	}
	if th.allow("1.2.3.4", now) {
		t.Fatal("a fourth attempt was allowed past a burst of three")
	}
	if !th.allow("5.6.7.8", now) {
		t.Fatal("a different key was refused: the buckets are not per key")
	}
	if !th.allow("1.2.3.4", now.Add(2*time.Second)) {
		t.Fatal("the bucket did not refill")
	}
}

// TestSourceIPRightmostUntrusted is the source_ip rule (docs/CONTRACTS.md §8): the
// socket peer by default, and with trust_proxy on, the RIGHTMOST entry that is not
// itself a trusted proxy. Never the leftmost.
func TestSourceIPRightmostUntrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.RemoteAddr = "127.0.0.1:51000"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")

	// trust_proxy off: the socket peer wins and the header is ignored entirely.
	if got := SourceIP(req, false); got != "127.0.0.1" {
		t.Fatalf("SourceIP without trust_proxy = %q, want the socket peer 127.0.0.1", got)
	}

	// trust_proxy on: 198.51.100.7 is the rightmost non-proxy hop. The leftmost
	// entry is what an attacker would have written.
	if got := SourceIP(req, true); got != "198.51.100.7" {
		t.Fatalf("SourceIP with trust_proxy = %q, want the rightmost untrusted entry 198.51.100.7", got)
	}

	// A chain that ends in a private address keeps walking left.
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.5")
	if got := SourceIP(req, true); got != "203.0.113.9" {
		t.Fatalf("SourceIP = %q, want 203.0.113.9 after skipping a private hop", got)
	}

	// Every entry trusted: fall back to the socket peer rather than inventing one.
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 127.0.0.1")
	if got := SourceIP(req, true); got != "127.0.0.1" {
		t.Fatalf("SourceIP = %q, want the socket peer when every hop is trusted", got)
	}

	// A rotated header cannot buy extra attempts: the same chain always resolves to
	// the same address, and the leftmost entry is never consulted.
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.7")
	if got := SourceIP(req, true); got != "198.51.100.7" {
		t.Fatalf("SourceIP = %q, want 198.51.100.7 and never the attacker-supplied leftmost", got)
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":        "127.0.0.1",
		"127.0.0.1:8080":   "127.0.0.1",
		"[::1]:8080":       "::1",
		"::1":              "::1",
		"::ffff:127.0.0.1": "127.0.0.1",
		"fe80::1%eth0":     "fe80::1",
		"":                 "",
		"not-an-address":   "",
		"999.999.999.999":  "",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	if got := bearerToken(req); got != "" {
		t.Fatalf("bearerToken with no header = %q", got)
	}
	req.Header.Set("Authorization", "Bearer cof_pat_abc")
	if got := bearerToken(req); got != "cof_pat_abc" {
		t.Fatalf("bearerToken = %q", got)
	}
	// The scheme is case-insensitive; the credential is not.
	req.Header.Set("Authorization", "bearer cof_pat_abc")
	if got := bearerToken(req); got != "cof_pat_abc" {
		t.Fatalf("bearerToken with a lowercase scheme = %q", got)
	}
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if got := bearerToken(req); got != "" {
		t.Fatalf("bearerToken accepted a Basic header: %q", got)
	}
}

func TestLooksLikeToken(t *testing.T) {
	if !looksLikeToken("cof_pat_" + strings.Repeat("a", 64)) {
		t.Error("a well-formed PAT was rejected")
	}
	if !looksLikeToken("cof_st_" + strings.Repeat("a", 64)) {
		t.Error("a well-formed service token was rejected")
	}
	for _, bad := range []string{
		"", "cof_pat_", "cof_pat_short", "Bearer cof_pat_" + strings.Repeat("a", 64),
		"cof_xxx_" + strings.Repeat("a", 64),
	} {
		if looksLikeToken(bad) {
			t.Errorf("looksLikeToken(%q) accepted a malformed credential", bad)
		}
	}
}

// TestRouteTableIsComplete pins the frozen route set (docs/CONTRACTS.md §4) so a
// route cannot silently disappear or appear.
func TestRouteTableIsComplete(t *testing.T) {
	want := []string{
		"POST /api/v1/auth/token",
		"POST /api/v1/auth/logout",
		"POST /api/v1/auth/password",
		"GET /api/v1/me",
		"GET /api/v1/admin/orgs",
		"POST /api/v1/admin/orgs",
		"POST /api/v1/admin/orgs/{org}/disable",
		"GET /api/v1/members",
		"POST /api/v1/members",
		"PATCH /api/v1/members/{user_id}",
		"DELETE /api/v1/members/{user_id}",
		"PUT /api/v1/members/{user_id}/grants/{project}",
		"DELETE /api/v1/members/{user_id}/grants/{project}",
		"GET /api/v1/projects",
		"POST /api/v1/projects",
		"GET /api/v1/projects/{p}/envs",
		"POST /api/v1/projects/{p}/envs",
		"GET /api/v1/tokens",
		"POST /api/v1/tokens",
		"DELETE /api/v1/tokens/{id}",
	}

	got := RoutePatterns()
	if len(got) != len(want) {
		t.Fatalf("registered %d routes, want %d: %v", len(got), len(want), got)
	}
	seen := make(map[string]bool, len(got))
	for _, r := range got {
		seen[r] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("route %q is not registered", w)
		}
	}
}

// TestMustChangeExemptListIsExactlyTwo is the allowlist half of P1(a). Every route
// except these two must be gated, and the gate is deny-by-default, so this is the
// only list that can open a hole.
func TestMustChangeExemptListIsExactlyTwo(t *testing.T) {
	exempt := map[string]bool{}
	for _, route := range RoutePatterns() {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			t.Fatalf("route %q has no method", route)
		}
		req := httptest.NewRequest(method, pattern, nil)
		if isMustChangeExempt(req) {
			exempt[route] = true
		}
	}

	wantExempt := map[string]bool{
		"POST /api/v1/auth/password": true,
		"POST /api/v1/auth/logout":   true,
	}
	for route := range wantExempt {
		if !exempt[route] {
			t.Errorf("route %q must be exempt from the must-change-password gate", route)
		}
	}
	for route := range exempt {
		if !wantExempt[route] {
			t.Errorf("route %q is exempt from the must-change-password gate but must not be", route)
		}
	}
}

func TestOnlyLoginIsPublic(t *testing.T) {
	for _, route := range RoutePatterns() {
		method, pattern, _ := strings.Cut(route, " ")
		req := httptest.NewRequest(method, pattern, nil)
		got := isPublicRoute(req)
		want := route == "POST /api/v1/auth/token"
		if got != want {
			t.Errorf("isPublicRoute(%q) = %v, want %v", route, got, want)
		}
	}
}

func TestStatusWriterRecordsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}

	sw.WriteHeader(http.StatusForbidden)
	sw.WriteHeader(http.StatusOK) // must be ignored: the first status wins

	if sw.status != http.StatusForbidden {
		t.Fatalf("statusWriter recorded %d, want 403", sw.status)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the underlying recorder saw %d, want 403", rec.Code)
	}
}
