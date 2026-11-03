//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Canonical error bodies (SPEC §2.1: invisible and missing are identical).
const (
	notFoundBody  = `{"error":{"code":"not_found","message":"not found"}}`
	testPassword  = "e2e-correct-horse-battery-staple"
	otherPassword = "e2e-another-long-password-42"
)

var (
	baseURL    string
	cliPath    string
	adminEmail string
	adminPass  string

	adminOnce  sync.Once
	adminTok   string
	adminErr   error
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func TestMain(m *testing.M) {
	baseURL = strings.TrimRight(envOr("COFFER_E2E_URL", "http://127.0.0.1:8420"), "/")
	cli := envOr("COFFER_E2E_CLI", filepath.Join("..", "..", "bin", "coffer"))
	abs, err := filepath.Abs(cli)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: resolve CLI path:", err)
		os.Exit(1)
	}
	cliPath = abs
	if _, err := os.Stat(cliPath); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: CLI binary %s not found (set COFFER_E2E_CLI or run ./scripts/build.sh): %v\n", cliPath, err)
		os.Exit(1)
	}
	adminEmail = envOr("COFFER_E2E_ADMIN_EMAIL", "admin@example.com")
	adminPass = os.Getenv("COFFER_E2E_ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = readDotEnv(filepath.Join("..", "..", ".env"), "COFFER_BOOTSTRAP_ADMIN_PASSWORD")
	}
	if adminPass == "" {
		fmt.Fprintln(os.Stderr, "e2e: platform admin password unknown (set COFFER_E2E_ADMIN_PASSWORD)")
		os.Exit(1)
	}
	resp, err := httpClient.Get(baseURL + "/readyz")
	if err != nil || resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "e2e: stack at %s is not ready: %v\n", baseURL, err)
		os.Exit(1)
	}
	_ = resp.Body.Close()
	os.Exit(m.Run())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func readDotEnv(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// rnd returns n random bytes as lowercase hex.
func rnd(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- HTTP

type resp struct {
	Status int
	Body   []byte
	Header http.Header
}

func (r resp) String() string { return fmt.Sprintf("%d %s", r.Status, r.Body) }

func (r resp) obj(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("response is not a JSON object: %v: %s", err, r.Body)
	}
	return m
}

func (r resp) arr(t testing.TB) []map[string]any {
	t.Helper()
	var a []map[string]any
	if err := json.Unmarshal(r.Body, &a); err != nil {
		t.Fatalf("response is not a JSON array: %v: %s", err, r.Body)
	}
	return a
}

func (r resp) errCode() string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Error.Code
}

// rawDo sends a request with an arbitrary body and headers.
func rawDo(t testing.TB, method, path, token string, body io.Reader, hdr map[string]string) resp {
	t.Helper()
	url := path
	if !strings.HasPrefix(path, "http") {
		url = baseURL + path
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp{Status: res.StatusCode, Body: b, Header: res.Header}
}

// api calls /api/v1 + path with an optional JSON body (nil = no body).
func api(t testing.TB, method, path, token string, body any) resp {
	t.Helper()
	var rd io.Reader
	hdr := map[string]string{}
	if body != nil {
		var b []byte
		switch v := body.(type) {
		case string:
			b = []byte(v)
		case []byte:
			b = v
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatalf("marshal: %v", err)
			}
		}
		rd = bytes.NewReader(b)
		hdr["Content-Type"] = "application/json"
	}
	return rawDo(t, method, "/api/v1"+path, token, rd, hdr)
}

// must asserts the status code and returns the response.
func must(t testing.TB, want int, r resp, what string) resp {
	t.Helper()
	if r.Status != want {
		t.Fatalf("%s: want status %d, got %s", what, want, r)
	}
	return r
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func num(m map[string]any, k string) int {
	f, _ := m[k].(float64)
	return int(f)
}

// ---------------------------------------------------------------- fixtures

func adminToken(t testing.TB) string {
	t.Helper()
	adminOnce.Do(func() {
		r := api(t, "POST", "/auth/token", "", map[string]string{"email": adminEmail, "password": adminPass})
		if r.Status != 201 && r.Status != 200 {
			adminErr = fmt.Errorf("platform admin login: %s", r)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(r.Body, &m)
		adminTok, _ = m["token"].(string)
		if adminTok == "" {
			adminErr = errors.New("platform admin login returned no token")
		}
	})
	if adminErr != nil {
		t.Fatal(adminErr)
	}
	return adminTok
}

type user struct {
	ID, Email, Role, Token string
}

type org struct {
	ID, Slug string
	Owner    user
}

// login returns a fresh PAT for email/password.
func login(t testing.TB, email, password string) string {
	t.Helper()
	r := api(t, "POST", "/auth/token", "", map[string]string{"email": email, "password": password})
	if r.Status != 201 && r.Status != 200 {
		t.Fatalf("login %s: %s", email, r)
	}
	tok := str(r.obj(t), "token")
	if !strings.HasPrefix(tok, "cof_pat_") {
		t.Fatalf("login %s: token %q lacks cof_pat_ prefix", email, tok)
	}
	return tok
}

// newOrg creates an org (unique slug) with a logged-in owner.
func newOrg(t testing.TB, label string) *org {
	t.Helper()
	slug := "e2e-" + label + "-" + rnd(4)
	email := "e2e-owner@" + slug + ".test"
	r := must(t, 201, api(t, "POST", "/admin/orgs", adminToken(t), map[string]string{
		"slug": slug, "owner_email": email, "owner_password": testPassword,
	}), "create org")
	m := r.obj(t)
	o := &org{ID: str(m, "id"), Slug: slug}
	tok := login(t, email, testPassword)
	me := must(t, 200, api(t, "GET", "/me", tok, nil), "me").obj(t)
	o.Owner = user{ID: str(me, "id"), Email: email, Role: "owner", Token: tok}
	return o
}

// addUser creates a member of o with the given role and logs them in.
func (o *org) addUser(t testing.TB, label, role string) user {
	t.Helper()
	email := "e2e-" + label + "-" + rnd(3) + "@" + o.Slug + ".test"
	r := must(t, 201, api(t, "POST", "/members", o.Owner.Token, map[string]string{
		"email": email, "role": role, "password": testPassword,
	}), "add member "+label)
	u := user{ID: str(r.obj(t), "id"), Email: email, Role: role}
	u.Token = login(t, email, testPassword)
	return u
}

func (o *org) project(t testing.TB, slug string, envs map[string]bool) {
	t.Helper()
	must(t, 201, api(t, "POST", "/projects", o.Owner.Token, map[string]string{"slug": slug}), "create project "+slug)
	for e, prot := range envs {
		must(t, 201, api(t, "POST", "/projects/"+slug+"/envs", o.Owner.Token, map[string]any{"slug": e, "protected": prot}), "create env "+e)
	}
}

func (o *org) grant(t testing.TB, u user, project, level string) {
	t.Helper()
	must(t, 200, api(t, "PUT", "/members/"+u.ID+"/grants/"+project, o.Owner.Token, map[string]string{"level": level}), "grant "+level)
}

type svcToken struct{ ID, Token string }

func (o *org) serviceToken(t testing.TB, project, env, access string, ttl int) svcToken {
	t.Helper()
	r := must(t, 201, api(t, "POST", "/tokens", o.Owner.Token, map[string]any{
		"project": project, "env": env, "access": access, "ttl_seconds": ttl, "name": "e2e-" + access,
	}), "issue service token")
	m := r.obj(t)
	return svcToken{ID: str(m, "id"), Token: str(m, "token")}
}

func setSecret(t testing.TB, tok, project, env, key, value string) int {
	t.Helper()
	r := must(t, 200, api(t, "PUT", secPath(project, env, key), tok, map[string]string{"value": value}), "set "+key)
	return num(r.obj(t), "version")
}

func secPath(project, env, key string) string {
	p := "/projects/" + project + "/envs/" + env + "/secrets"
	if key != "" {
		p += "/" + key
	}
	return p
}

// auditEvents fetches the caller's org audit log (newest first).
func auditEvents(t testing.TB, tok, query string) []map[string]any {
	t.Helper()
	return must(t, 200, api(t, "GET", "/audit?"+query, tok, nil), "audit list").arr(t)
}

// ---------------------------------------------------------------- CLI

type cliResult struct {
	Code           int
	Stdout, Stderr []byte
}

func (c cliResult) String() string {
	return fmt.Sprintf("exit=%d stdout=%q stderr=%q", c.Code, c.Stdout, c.Stderr)
}

// cli runs the coffer binary. cfgHome becomes XDG_CONFIG_HOME (and HOME), token
// (if non-empty) becomes COFFER_TOKEN. extraEnv entries are appended.
type cliEnv struct {
	CfgHome string
	Token   string
	Extra   []string
}

func newCLIEnv(t testing.TB) *cliEnv {
	return &cliEnv{CfgHome: t.TempDir()}
}

func (c *cliEnv) environ() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + c.CfgHome,
		"XDG_CONFIG_HOME=" + c.CfgHome,
		"COFFER_URL=" + baseURL,
		"LANG=C.UTF-8",
	}
	if c.Token != "" {
		env = append(env, "COFFER_TOKEN="+c.Token)
	}
	return append(env, c.Extra...)
}

func (c *cliEnv) run(t testing.TB, stdin []byte, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(cliPath, args...)
	cmd.Env = c.environ()
	cmd.Dir = c.CfgHome
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run coffer %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return cliResult{Code: code, Stdout: out.Bytes(), Stderr: errb.Bytes()}
}

// ok runs a CLI command and requires the given exit code.
func (c *cliEnv) want(t testing.TB, code int, stdin []byte, args ...string) cliResult {
	t.Helper()
	r := c.run(t, stdin, args...)
	if r.Code != code {
		t.Fatalf("coffer %s: want exit %d, got %s", strings.Join(args, " "), code, r)
	}
	return r
}
