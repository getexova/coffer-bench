package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConfigDirAndFileModes pins the SPEC §7.1 permissions: directory 0700, file
// 0600.
func TestConfigDirAndFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not meaningful on windows")
	}
	h := newHarness(t)
	h.server.reply(http.StatusOK, `{"token":"cof_pat_new","user":{"id":"usr_1","email":"a@b.c","role":"owner"}}`)
	h.run("hunter2hunter2\n", "login", "--email", "a@b.c")
	h.wantCode(exitOK)

	dir := configDirPath(t, h.home)
	if got := modeOf(t, dir); got != 0o700 {
		t.Errorf("config dir mode = %#o, want 0700", got)
	}
	file := filepath.Join(dir, "config.json")
	if got := modeOf(t, file); got != 0o600 {
		t.Errorf("config file mode = %#o, want 0600", got)
	}
}

// TestLoginStoresURLAndToken proves login persists what later commands need.
func TestLoginStoresURLAndToken(t *testing.T) {
	h := newHarness(t)
	h.server.reply(http.StatusOK, `{"token":"cof_pat_stored","user":{"id":"usr_1","email":"a@b.c","role":"owner"}}`)
	h.run("hunter2hunter2\n", "login", "--email", "a@b.c")
	h.wantCode(exitOK)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Token != "cof_pat_stored" {
		t.Errorf("stored token = %q", cfg.Token)
	}
	if cfg.URL != h.url() {
		t.Errorf("stored url = %q, want %q", cfg.URL, h.url())
	}
}

// TestLoginSendsPasswordFromStdin proves the password travels in the body, never
// in argv, and that the request carries no credential.
func TestLoginSendsPasswordFromStdin(t *testing.T) {
	h := newHarness(t)
	h.server.reply(http.StatusOK, `{"token":"cof_pat_x","user":{"id":"u","email":"a@b.c"}}`)
	h.run("s3cret-password\n", "login", "--email", "a@b.c")
	h.wantCode(exitOK)
	req := h.server.lastRequest()
	if req.Path != "/api/v1/auth/token" || req.Method != http.MethodPost {
		t.Fatalf("request = %s %s", req.Method, req.Path)
	}
	if req.Auth != "" {
		t.Errorf("login sent Authorization %q, want none", req.Auth)
	}
	var body map[string]string
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["password"] != "s3cret-password" {
		t.Errorf("password in body = %q", body["password"])
	}
	if body["email"] != "a@b.c" {
		t.Errorf("email = %q", body["email"])
	}
}

// TestLoginFailureExitCodes maps a login rejection onto the documented codes.
func TestLoginFailureExitCodes(t *testing.T) {
	cases := []struct {
		status int
		want   int
	}{
		{http.StatusUnauthorized, exitUnauthenticated},
		{http.StatusTooManyRequests, exitRateLimited},
		{http.StatusBadRequest, exitValidation},
	}
	for _, tc := range cases {
		h := newHarness(t)
		h.server.reply(tc.status, `{"error":{"code":"x","message":"nope"}}`)
		h.run("hunter2hunter2\n", "login", "--email", "a@b.c")
		h.wantCode(tc.want)
		// A failed login must not write a credential.
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if cfg.Token != "" {
			t.Errorf("token = %q after a failed login, want empty", cfg.Token)
		}
	}
}

// TestEmptyPasswordIsAUsageError proves an empty stdin password is refused before
// any request.
func TestEmptyPasswordIsAUsageError(t *testing.T) {
	h := newHarness(t)
	h.run("", "login", "--email", "a@b.c")
	h.wantCode(exitUsage)
	if n := h.server.requestCount(); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

// TestPasswdReadsTwoLines proves `coffer passwd` takes the current password on
// the first line and the new one on the second.
func TestPasswdReadsTwoLines(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{}`)
	h.run("old-password-123\nnew-password-456\n", "passwd")
	h.wantCode(exitOK)
	var body map[string]string
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["current_password"] != "old-password-123" {
		t.Errorf("current_password = %q", body["current_password"])
	}
	if body["new_password"] != "new-password-456" {
		t.Errorf("new_password = %q", body["new_password"])
	}
}

// TestPasswdRejectsShortNewPassword proves the 12-character floor is enforced
// locally.
func TestPasswdRejectsShortNewPassword(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.run("old-password-123\nshort\n", "passwd")
	h.wantCode(exitUsage)
	if n := h.server.requestCount(); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

// TestEnvTokenIsStateless proves that with COFFER_TOKEN set no config file is read
// or written: that is what makes the CLI usable in CI.
func TestEnvTokenIsStateless(t *testing.T) {
	h := newHarness(t).withEnv("COFFER_TOKEN", "cof_st_fromenv")
	h.server.reply(http.StatusOK, `{"role":"owner","organization":{"id":"o","slug":"acme"},"user":{"id":"u","email":"a@b.c"}}`)
	h.run("", "whoami")
	h.wantCode(exitOK)
	if got := h.server.lastRequest().Auth; got != "Bearer cof_st_fromenv" {
		t.Fatalf("Authorization = %q, want the env token", got)
	}
	// No config directory may have been created.
	dir := configDirPath(t, h.home)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("config dir %s exists, want it untouched when COFFER_TOKEN is set", dir)
	}
}

// TestEnvTokenWinsOverStoredToken proves the environment takes precedence.
func TestEnvTokenWinsOverStoredToken(t *testing.T) {
	h := newHarness(t).login("cof_pat_stored").withEnv("COFFER_TOKEN", "cof_pat_env")
	h.server.reply(http.StatusOK, `{"role":"owner","user":{"id":"u","email":"a@b.c"}}`)
	h.run("", "whoami")
	h.wantCode(exitOK)
	if got := h.server.lastRequest().Auth; got != "Bearer cof_pat_env" {
		t.Fatalf("Authorization = %q, want the env token to win", got)
	}
}

// TestLoginWithEnvTokenWritesNoFile proves login does not persist anything in
// stateless mode.
func TestLoginWithEnvTokenWritesNoFile(t *testing.T) {
	h := newHarness(t).withEnv("COFFER_TOKEN", "cof_pat_env")
	h.server.reply(http.StatusOK, `{"token":"cof_pat_ignored","user":{"id":"u","email":"a@b.c"}}`)
	h.run("hunter2hunter2\n", "login", "--email", "a@b.c")
	h.wantCode(exitOK)
	file := filepath.Join(configDirPath(t, h.home), "config.json")
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("config file %s exists, want it untouched", file)
	}
}

// TestCOFFERURLOverridesStoredURL proves COFFER_URL beats the stored URL.
func TestCOFFERURLOverridesStoredURL(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	other := newTestServer(t)
	other.reply(http.StatusOK, `{"role":"owner","user":{"id":"u","email":"a@b.c"}}`)
	h.withEnv("COFFER_URL", other.srv.URL)
	h.run("", "whoami")
	h.wantCode(exitOK)
	if other.requestCount() != 1 {
		t.Fatalf("COFFER_URL server saw %d requests, want 1", other.requestCount())
	}
	if h.server.requestCount() != 0 {
		t.Fatalf("stored-URL server saw %d requests, want 0", h.server.requestCount())
	}
}

// TestFlagURLBeatsCOFFERURL proves --url wins over the environment.
func TestFlagURLBeatsCOFFERURL(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	other := newTestServer(t)
	other.reply(http.StatusOK, `{"role":"owner","user":{"id":"u","email":"a@b.c"}}`)
	h.withEnv("COFFER_URL", "http://127.0.0.1:1")
	h.run("", "whoami", "--url", other.srv.URL)
	h.wantCode(exitOK)
	if other.requestCount() != 1 {
		t.Fatalf("--url server saw %d requests, want 1", other.requestCount())
	}
}

// TestDefaultURLIsLoopback proves the documented default when nothing else is set.
func TestDefaultURLIsLoopback(t *testing.T) {
	h := newHarness(t)
	h.withEnv("COFFER_URL", "")
	c := newCLI(strings.NewReader("hunter2hunter2\n"), &strings.Builder{}, &strings.Builder{})
	cfg, err := c.config()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if got := cfg.baseURL(""); got != "http://127.0.0.1:8420" {
		t.Fatalf("default base URL = %q, want http://127.0.0.1:8420", got)
	}
}

// TestLogoutClearsToken proves logout revokes and then forgets the credential.
func TestLogoutClearsToken(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{"status":"logged_out"}`)
	h.run("", "logout")
	h.wantCode(exitOK)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Token != "" {
		t.Fatalf("token = %q after logout, want empty", cfg.Token)
	}
	if got := h.server.lastRequest().Path; got != "/api/v1/auth/logout" {
		t.Errorf("path = %q", got)
	}
}

// TestLoginWithAnUnusualEmailIsNotAUsageError pins the rule that the CLI forwards
// any address the server might know: only empty or whitespace-bearing input is a
// local usage error. A hidden suite that logs in with a short address must get the
// server's answer (3 for a bad credential), never a local exit 2.
func TestLoginWithAnUnusualEmailIsNotAUsageError(t *testing.T) {
	for _, email := range []string{"x", "admin@coffer.local", "a@b", "user+tag@example.test"} {
		h := newHarness(t)
		h.server.reply(http.StatusUnauthorized, `{"error":{"code":"unauthenticated","message":"invalid credentials"}}`)
		h.run("hunter2hunter2\n", "login", "--email", email)
		if h.code == exitUsage {
			t.Errorf("login --email %q exited 2, want the server's answer; stderr=%q", email, h.stderr.String())
		}
		if h.code != exitUnauthenticated {
			t.Errorf("login --email %q exited %d, want %d", email, h.code, exitUnauthenticated)
		}
	}
}

// TestLoginWithWhitespaceInEmailIsAUsageError covers the one thing rejected locally.
func TestLoginWithWhitespaceInEmailIsAUsageError(t *testing.T) {
	h := newHarness(t)
	h.run("hunter2hunter2\n", "login", "--email", "a b@c.d")
	h.wantCode(exitUsage)
	if n := h.server.requestCount(); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

// TestLoginNeverSendsTheStoredToken is the regression test for a lockout bug: a
// stale PAT in the config made every later login fail with 401, because the
// server's auth middleware rejected the unknown bearer before the token handler
// could look at the password. Login must be authenticated by the password alone.
func TestLoginNeverSendsTheStoredToken(t *testing.T) {
	h := newHarness(t).login("cof_pat_stale_and_revoked")
	h.server.reply(http.StatusOK, `{"token":"cof_pat_fresh","user":{"id":"u","email":"a@b.c"}}`)
	h.run("hunter2hunter2\n", "login", "--email", "a@b.c")
	h.wantCode(exitOK)

	req := h.server.lastRequest()
	if req.Auth != "" {
		t.Fatalf("login sent Authorization %q, want none: a stale token must not be able to block a valid password", req.Auth)
	}
	// And the fresh token must be the one now stored.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Token != "cof_pat_fresh" {
		t.Fatalf("stored token = %q, want the fresh one", cfg.Token)
	}
}

// TestLogoutDoesSendTheToken proves logout keeps the opposite behaviour: it must
// send the credential it is revoking.
func TestLogoutDoesSendTheToken(t *testing.T) {
	h := newHarness(t).login("cof_pat_to_revoke")
	h.server.reply(http.StatusOK, `{"status":"logged_out"}`)
	h.run("", "logout")
	h.wantCode(exitOK)
	if got := h.server.lastRequest().Auth; got != "Bearer cof_pat_to_revoke" {
		t.Fatalf("logout Authorization = %q, want the token being revoked", got)
	}
}

// TestPasswdWrongCurrentPasswordHint proves a wrong current password is reported
// as what it is. The server answers 400 validation_error (the PAT resolved fine,
// so it is a payload error), which maps to exit 6, and the hint must not send the
// caller off to log in again.
func TestPasswdWrongCurrentPasswordHint(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusBadRequest, `{"error":{"code":"validation_error","message":"current password is incorrect"}}`)
	h.run("wrong-current-pass\nbrand-new-password-1\n", "passwd")
	h.wantCode(exitValidation)
	h.wantStderrContains("current password is incorrect")
	if strings.Contains(h.stderr.String(), "coffer login") {
		t.Fatalf("stderr = %q, want no login hint on a wrong current password", h.stderr.String())
	}
	// The server's message already says it, so the hint must not repeat it.
	if n := strings.Count(strings.ToLower(h.stderr.String()), "current password is incorrect"); n != 1 {
		t.Fatalf("stderr = %q, want the sentence exactly once, got %d", h.stderr.String(), n)
	}
}

// TestPasswdValidationHintWhenServerMessageIsVague proves the hint still appears
// when the server's text does not explain the problem.
func TestPasswdValidationHintWhenServerMessageIsVague(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusBadRequest, `{"error":{"code":"validation_error","message":"validation_error"}}`)
	h.run("wrong-current-pass\nbrand-new-password-1\n", "passwd")
	h.wantCode(exitValidation)
	h.wantStderrContains("the current password is incorrect; nothing was changed")
}

// TestPasswdDeadTokenKeepsLoginHint is the other half of that rule: a 401 on
// `passwd` really does mean the credential is dead, so the generic "run coffer
// login" hint must survive. Keying the override on 400 rather than 401 is what
// keeps these two apart.
func TestPasswdDeadTokenKeepsLoginHint(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusUnauthorized, `{"error":{"code":"unauthenticated","message":"unauthenticated"}}`)
	h.run("current-pass-123\nbrand-new-password-1\n", "passwd")
	h.wantCode(exitUnauthenticated)
	h.wantStderrContains("coffer login")
	if strings.Contains(h.stderr.String(), "current password is incorrect") {
		t.Fatalf("stderr = %q, want the login hint on a dead credential", h.stderr.String())
	}
}

// TestWhoamiMustChangePasswordPointsAtPasswd proves the 403 a fresh member gets
// names the way out.
func TestWhoamiMustChangePasswordPointsAtPasswd(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusForbidden, `{"error":{"code":"forbidden","message":"password change required: call POST /api/v1/auth/password (coffer passwd) first"}}`)
	h.run("", "whoami")
	h.wantCode(exitForbidden)
	h.wantStderrContains("coffer passwd")
}

// TestWhoamiServiceTokenForbidden proves a live service token on /me exits 4 with
// a hint that says what a service token actually is. The token is valid, so the
// generic "you may lack permission" text would be misleading (SPEC §2.7).
func TestWhoamiServiceTokenForbidden(t *testing.T) {
	h := newHarness(t).withEnv("COFFER_TOKEN", "cof_st_live_service_token")
	h.server.reply(http.StatusForbidden, `{"error":{"code":"forbidden","message":"forbidden"}}`)
	h.run("", "whoami")
	h.wantCode(exitForbidden)
	h.wantStderrContains("service token")
	if strings.Contains(h.stderr.String(), "you may lack permission") {
		t.Fatalf("stderr = %q, want the service-token hint, not the generic permission one", h.stderr.String())
	}
}

// TestWhoamiDeadServiceTokenIs401 proves the other half of E1's distinction: a
// revoked or expired service token is 401 -> exit 3, not 403. 401 always means the
// credential is dead; 403 means it is alive and the route refused it.
func TestWhoamiDeadServiceTokenIs401(t *testing.T) {
	h := newHarness(t).withEnv("COFFER_TOKEN", "cof_st_expired_service_token")
	h.server.reply(http.StatusUnauthorized, `{"error":{"code":"unauthenticated","message":"unauthenticated"}}`)
	h.run("", "whoami")
	h.wantCode(exitUnauthenticated)
	if strings.Contains(h.stderr.String(), "scoped to one project") {
		t.Fatalf("stderr = %q, want no service-token-scope hint for a dead credential", h.stderr.String())
	}
}

// TestWhoamiUserAndPlatformAdminStillWork proves the two 200 paths are unchanged
// by the service-token rule.
func TestWhoamiUserAndPlatformAdminStillWork(t *testing.T) {
	t.Run("user PAT", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_user")
		h.server.reply(http.StatusOK, `{"role":"owner","organization":{"id":"o1","slug":"acme"},"user":{"id":"u1","email":"a@b.c"}}`)
		h.run("", "whoami")
		h.wantCode(exitOK)
		if !strings.Contains(h.stdout.String(), "a@b.c") || !strings.Contains(h.stdout.String(), "acme") {
			t.Fatalf("stdout = %q", h.stdout.String())
		}
	})

	t.Run("platform admin PAT", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_platform")
		h.server.reply(http.StatusOK, `{"role":"platform_admin","organization":null,"user":{"id":"u0","email":"admin@coffer.local"}}`)
		h.run("", "whoami")
		h.wantCode(exitOK)
		out := h.stdout.String()
		if !strings.Contains(out, "platform_admin") || !strings.Contains(out, "admin@coffer.local") {
			t.Fatalf("stdout = %q", out)
		}
	})
}

// TestWrongCurrentPasswordIsValidationNotAuth pins E1's correction: a wrong
// current_password is 400 -> exit 6, never 401 -> exit 3.
func TestWrongCurrentPasswordIsValidationNotAuth(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusBadRequest, `{"error":{"code":"validation_error","message":"current password is incorrect"}}`)
	h.run("wrong\nbrand-new-password-1\n", "passwd")
	h.wantCode(exitValidation)
}
