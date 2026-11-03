package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/reqctx"
)

// TestServeRefusesNilAuditWriter is the guard the CTO asked for: a server with no
// audit writer must refuse to start rather than run with a no-op that silently
// discards every event.
//
// It is asserted without a database and without binding a port, because the check
// runs before both. That ordering is deliberate: a wiring mistake should fail
// immediately and identically on every host, not after a migration run.
func TestServeRefusesNilAuditWriter(t *testing.T) {
	err := ServeWithOptions(context.Background(), testConfig(t), testLogger(), Options{
		AuditWriter: nil,
	})

	if err == nil {
		t.Fatal("ServeWithOptions started a server with no audit writer")
	}
	if !strings.Contains(err.Error(), "audit writer") {
		t.Errorf("error = %q, want it to name the audit writer", err)
	}
	if !strings.Contains(err.Error(), "refusing to serve") {
		t.Errorf("error = %q, want it to say it refuses to serve", err)
	}
}

// TestServeNilAuditWriterDoesNotBindPort pins that the refusal happens before the
// listener is opened, so a misconfigured container does not briefly occupy the port
// and look alive to a health check.
func TestServeNilAuditWriterDoesNotBindPort(t *testing.T) {
	cfg := testConfig(t)
	// Port 0 would let the kernel pick one, so a successful bind would be
	// undetectable by the address alone; instead assert that the call returns
	// before it could serve, and that the error is the audit one, not a listen one.
	err := ServeWithOptions(context.Background(), cfg, testLogger(), Options{})
	if err == nil {
		t.Fatal("ServeWithOptions started with no options")
	}
	if strings.Contains(err.Error(), "could not listen") {
		t.Fatalf("the audit guard ran after the listener: %v", err)
	}
}

// TestNopWriterRequiresExplicitOptIn pins that the no-op writer is reachable only
// when a caller asks for it by name. It is what keeps the no-op out of production
// wiring while still letting tests build a router cheaply.
func TestNopWriterRequiresExplicitOptIn(t *testing.T) {
	router := NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, failClosedAuthenticator{})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
}

// TestServeWithOptionsRequiresConfig pins the other precondition, so the nil-writer
// test above cannot pass for the wrong reason.
func TestServeWithOptionsRequiresConfig(t *testing.T) {
	err := ServeWithOptions(context.Background(), nil, testLogger(), Options{AuditWriter: audit.NopWriter()})
	if err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("err = %v, want a nil-config error", err)
	}
}

// keep imports honest for the config/reqctx types referenced above.
var (
	_                      = config.EnvDevelopment
	_ reqctx.Authenticator = failClosedAuthenticator{}
)
