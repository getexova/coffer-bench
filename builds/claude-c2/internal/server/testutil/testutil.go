// Package testutil provides an integration-test harness: a fresh, randomly
// named Postgres database per test (from COFFER_TEST_DATABASE_URL), a booted
// Coffer server behind httptest, and a small HTTP client. Tests skip when
// COFFER_TEST_DATABASE_URL is unset.
package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/coffer-dev/coffer/internal/server/app"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

// AdminEmail / AdminPassword are the bootstrap platform admin credentials.
const (
	AdminEmail    = "platform@example.com"
	AdminPassword = "platform-admin-password"
)

// DSN returns COFFER_TEST_DATABASE_URL or skips the test.
func DSN(t testing.TB) string {
	dsn := os.Getenv("COFFER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("COFFER_TEST_DATABASE_URL not set; skipping integration test")
	}
	return dsn
}

// DB is a fresh test database.
type DB struct {
	Name     string
	DSN      string // owner DSN for the test database
	Role     string // app role name for this database
	Owner    *pgxpool.Pool
	adminDSN string
}

func withDB(dsn, name string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + name
	return u.String()
}

// NewDB creates a fresh database and registers cleanup.
func NewDB(t testing.TB) *DB {
	t.Helper()
	admin := DSN(t)
	suffix := hex.EncodeToString(crypto.RandomBytes(6))
	d := &DB{Name: "coffer_test_" + suffix, Role: "coffer_app_" + suffix, adminDSN: admin}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin dsn: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{d.Name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	d.DSN = withDB(admin, d.Name)
	d.Owner, err = pgxpool.New(ctx, d.DSN)
	if err != nil {
		t.Fatalf("owner pool: %v", err)
	}
	t.Cleanup(func() {
		d.Owner.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{d.Name}.Sanitize()+" WITH (FORCE)")
		c.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{d.Role}.Sanitize())
	})
	return d
}

// Config returns a valid test configuration for d.
func (d *DB) Config(masterKey []byte) *config.Config {
	return &config.Config{
		MasterKey:         masterKey,
		BootstrapEmail:    AdminEmail,
		BootstrapPassword: AdminPassword,
		ListenAddr:        "127.0.0.1:0",
		DatabaseURL:       d.DSN,
		PATTTL:            24 * time.Hour,
		Argon2MemoryKiB:   config.MinArgon2MemoryKiB,
		AppRole:           d.Role,
	}
}

// Server is a booted Coffer instance behind httptest.
type Server struct {
	App  *app.App
	HTTP *httptest.Server
	URL  string
	DB   *DB
	logs *lockedBuffer
}

// Boot starts a server on d with cfg (nil => d.Config(random key)).
func Boot(t testing.TB, d *DB, cfg *config.Config) *Server {
	t.Helper()
	if cfg == nil {
		cfg = d.Config(crypto.RandomBytes(32))
	}
	logs := &lockedBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	a := app.New(cfg, log)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.Boot(ctx); err != nil {
		t.Fatalf("boot: %v", err)
	}
	hs := httptest.NewServer(a.API)
	s := &Server{App: a, HTTP: hs, URL: hs.URL, DB: d, logs: logs}
	t.Cleanup(func() {
		hs.Close()
		a.Close()
		if t.Failed() && os.Getenv("COFFER_TEST_LOGS") != "" {
			t.Logf("server logs:\n%s", logs.String())
		}
	})
	return s
}

// New is NewDB + Boot.
func New(t testing.TB) *Server {
	return Boot(t, NewDB(t), nil)
}

// LogText returns everything the server logged so far.
func (s *Server) LogText() string { return s.logs.String() }

// ---------------------------------------------------------------- client

// Resp is an HTTP response with its body read.
type Resp struct {
	Status int
	Body   []byte
	Header http.Header
}

// JSON decodes the body into v (fails the test on error).
func (r *Resp) JSON(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
}

// Map decodes the body as an object.
func (r *Resp) Map(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	r.JSON(t, &m)
	return m
}

// Client calls the API with an optional bearer token.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// Client returns a client for s with token.
func (s *Server) Client(token string) *Client {
	return &Client{Base: s.URL, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Do sends method path (relative to /api/v1 unless it starts with "//" or
// "/healthz" etc. — use Raw for those) with body (string, []byte, nil, or
// any JSON-marshalable value).
func (c *Client) Do(t testing.TB, method, path string, body any) *Resp {
	t.Helper()
	return c.Raw(t, method, "/api/v1"+path, body, nil)
}

// Raw sends a request to an absolute server path.
func (c *Client) Raw(t testing.TB, method, path string, body any, hdr map[string]string) *Resp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.Base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &Resp{Status: resp.StatusCode, Body: b, Header: resp.Header}
}

// Must sends a request and fails the test unless the status matches.
func (c *Client) Must(t testing.TB, want int, method, path string, body any) *Resp {
	t.Helper()
	r := c.Do(t, method, path, body)
	if r.Status != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, r.Status, want, r.Body)
	}
	return r
}

// Login returns a PAT for email/password.
func (s *Server) Login(t testing.TB, email, password string) string {
	t.Helper()
	r := s.Client("").Must(t, 201, "POST", "/auth/token", map[string]string{"email": email, "password": password})
	var out struct {
		Token string `json:"token"`
	}
	r.JSON(t, &out)
	return out.Token
}

// RandomKey returns a fresh base64 master key and its bytes.
func RandomKey() (string, []byte) {
	k := crypto.RandomBytes(32)
	return base64.StdEncoding.EncodeToString(k), k
}

// RandomKeyBytes returns a fresh 32-byte master key.
func RandomKeyBytes() []byte { return crypto.RandomBytes(32) }
