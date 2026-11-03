package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// validKey is a real 32-byte key, base64 encoded.
func validKey() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

// baseEnv is a complete, valid production environment. Each test removes or changes
// one variable.
func baseEnv() map[string]string {
	return map[string]string{
		"COFFER_MASTER_KEY":               validKey(),
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "Admin@Example.COM",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "correct-horse-battery",
		"COFFER_ENV":                      "production",
		"COFFER_APP_DB_PASSWORD":          "app-password",
		"POSTGRES_USER":                   "coffer_owner",
		"POSTGRES_PASSWORD":               "owner-password",
		"POSTGRES_DB":                     "coffer",
	}
}

func lookupFrom(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	env := baseEnv()
	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %d, want %d", cfg.Port, DefaultPort)
	}
	if cfg.BindAddr != DefaultBindAddr {
		t.Errorf("BindAddr = %q, want %q", cfg.BindAddr, DefaultBindAddr)
	}
	if cfg.Env != EnvProduction {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvProduction)
	}
	if cfg.TrustProxy {
		t.Error("TrustProxy = true, want false by default")
	}
	if cfg.DB.Host != DefaultDBHost || cfg.DB.Port != DefaultDBPort || cfg.DB.SSLMode != DefaultDBSSLMode {
		t.Errorf("DB defaults = %s/%d/%s, want %s/%d/%s",
			cfg.DB.Host, cfg.DB.Port, cfg.DB.SSLMode,
			DefaultDBHost, DefaultDBPort, DefaultDBSSLMode)
	}
	if len(cfg.MasterKey) != MasterKeyLen {
		t.Errorf("MasterKey length = %d, want %d", len(cfg.MasterKey), MasterKeyLen)
	}
	if cfg.BootstrapAdminEmail != "admin@example.com" {
		t.Errorf("BootstrapAdminEmail = %q, want it lowercased", cfg.BootstrapAdminEmail)
	}
	if cfg.Addr() != "127.0.0.1:8420" {
		t.Errorf("Addr() = %q, want 127.0.0.1:8420", cfg.Addr())
	}
	if !cfg.IsLoopback() {
		t.Error("IsLoopback() = false for the default bind address")
	}
	if cfg.Degraded() {
		t.Error("Degraded() = true with an app password set")
	}
	if cfg.DB.Mode != RoleApp {
		t.Errorf("DB.Mode = %q, want %q", cfg.DB.Mode, RoleApp)
	}
}

func TestLoadMissingRequiredNamesTheVariable(t *testing.T) {
	for _, name := range []string{
		"COFFER_MASTER_KEY",
		"COFFER_BOOTSTRAP_ADMIN_EMAIL",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_DB",
	} {
		t.Run(name, func(t *testing.T) {
			env := baseEnv()
			delete(env, name)

			_, err := LoadFrom(lookupFrom(env))
			if err == nil {
				t.Fatalf("LoadFrom succeeded with %s missing", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q does not name %s", err, name)
			}
			var missing *MissingEnvError
			if !asMissing(err, &missing) {
				t.Errorf("error %q is not a *MissingEnvError", err)
			}
		})
	}
}

func asMissing(err error, target **MissingEnvError) bool {
	m, ok := err.(*MissingEnvError)
	if ok {
		*target = m
	}
	return ok
}

func TestLoadEmptyStringIsUnset(t *testing.T) {
	// compose passes every .env key into the container, so an optional variable is
	// present with an empty value rather than absent. That must behave as unset.
	env := baseEnv()
	env["COFFER_MASTER_KEY_PREVIOUS"] = ""
	env["COFFER_MIGRATION_DATABASE_URL"] = ""
	env["DATABASE_URL"] = ""
	env["COFFER_TRUST_PROXY"] = ""
	env["COFFER_PORT"] = ""

	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom with empty optional values: %v", err)
	}
	if cfg.MasterKeyPrevious != nil {
		t.Error("MasterKeyPrevious set from an empty variable")
	}
	if cfg.Port != DefaultPort {
		t.Errorf("Port = %d, want the default from an empty variable", cfg.Port)
	}
}

func TestMasterKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"placeholder", PlaceholderMasterKey, "placeholder"},
		{"placeholder-like", "REPLACE_WITH_YOUR_KEY_HERE_32BYTES!!", "placeholder"},
		{"not base64", "not base64 at all!!!", "base64"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16)), "32 bytes"},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 33)), "32 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv()
			env["COFFER_MASTER_KEY"] = tt.value

			_, err := LoadFrom(lookupFrom(env))
			if err == nil {
				t.Fatalf("LoadFrom accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
			// A key must never be echoed in an error.
			if tt.value != PlaceholderMasterKey && strings.Contains(err.Error(), tt.value) {
				t.Errorf("error %q echoes the key value", err)
			}
		})
	}
}

func TestBootstrapPasswordLength(t *testing.T) {
	tests := []struct {
		password string
		ok       bool
	}{
		{"short", false},
		{"elevenchars", false},
		{"twelve_chars", true},
		{"a-much-longer-password", true},
	}
	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			env := baseEnv()
			env["COFFER_BOOTSTRAP_ADMIN_PASSWORD"] = tt.password

			_, err := LoadFrom(lookupFrom(env))
			if tt.ok && err != nil {
				t.Errorf("LoadFrom rejected a %d-character password: %v", len(tt.password), err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("LoadFrom accepted a %d-character password", len(tt.password))
				}
				if !strings.Contains(err.Error(), "COFFER_BOOTSTRAP_ADMIN_PASSWORD") {
					t.Errorf("error %q does not name the variable", err)
				}
			}
		})
	}
}

// TestDegradedRoleGate covers docs/CONTRACTS.md §11 exactly.
func TestDegradedRoleGate(t *testing.T) {
	tests := []struct {
		name         string
		appPassword  string
		allowFlag    string
		env          string
		wantErr      bool
		wantMention  []string
		wantMode     RoleMode
		wantWarnings bool
	}{
		{
			name:        "app password present",
			appPassword: "app-password",
			env:         "production",
			wantMode:    RoleApp,
		},
		{
			name:        "neither variable in production",
			env:         "production",
			wantErr:     true,
			wantMention: []string{"COFFER_APP_DB_PASSWORD", "COFFER_ALLOW_DEGRADED_DB_ROLE"},
		},
		{
			name:        "neither variable in development",
			env:         "development",
			wantErr:     true,
			wantMention: []string{"COFFER_APP_DB_PASSWORD", "COFFER_ALLOW_DEGRADED_DB_ROLE"},
		},
		{
			name:        "degraded flag in production is refused",
			allowFlag:   "1",
			env:         "production",
			wantErr:     true,
			wantMention: []string{"COFFER_ALLOW_DEGRADED_DB_ROLE", "COFFER_APP_DB_PASSWORD"},
		},
		{
			name:         "degraded flag in development proceeds with a warning",
			allowFlag:    "1",
			env:          "development",
			wantMode:     RoleOwnerDegraded,
			wantWarnings: true,
		},
		{
			name:         "app password and flag together use the app role",
			appPassword:  "app-password",
			allowFlag:    "1",
			env:          "development",
			wantMode:     RoleApp,
			wantWarnings: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv()
			env["COFFER_ENV"] = tt.env
			if tt.appPassword == "" {
				delete(env, "COFFER_APP_DB_PASSWORD")
			} else {
				env["COFFER_APP_DB_PASSWORD"] = tt.appPassword
			}
			if tt.allowFlag == "" {
				delete(env, "COFFER_ALLOW_DEGRADED_DB_ROLE")
			} else {
				env["COFFER_ALLOW_DEGRADED_DB_ROLE"] = tt.allowFlag
			}

			cfg, err := LoadFrom(lookupFrom(env))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LoadFrom accepted an invalid degraded configuration (mode %q)", cfg.DB.Mode)
				}
				for _, want := range tt.wantMention {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not name %s", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			if cfg.DB.Mode != tt.wantMode {
				t.Errorf("DB.Mode = %q, want %q", cfg.DB.Mode, tt.wantMode)
			}
			if tt.wantWarnings && len(cfg.Warnings) == 0 {
				t.Error("expected a warning, got none")
			}
			// A degraded boot must say what isolation is lost.
			if tt.wantMode == RoleOwnerDegraded {
				joined := strings.Join(cfg.Warnings, " ")
				if !strings.Contains(joined, AppDBRole) {
					t.Errorf("degraded warning does not name the lost isolation: %q", joined)
				}
			}
		})
	}
}

func TestDatabaseURLs(t *testing.T) {
	env := baseEnv()
	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	// The migration URL is the owner; the runtime URL is coffer_app.
	if !strings.Contains(cfg.MigrationURL(), "coffer_owner") {
		t.Errorf("MigrationURL does not use the owner role: %s", cfg.MigrationURL())
	}
	if !strings.Contains(cfg.RuntimeURL(), AppDBRole) {
		t.Errorf("RuntimeURL does not use %s: %s", AppDBRole, cfg.RuntimeURL())
	}
	if strings.Contains(cfg.RuntimeURL(), "owner-password") {
		t.Error("RuntimeURL carries the owner password")
	}

	// Explicit overrides win.
	env["DATABASE_URL"] = "postgres://someone@db.internal:5432/coffer?sslmode=require"
	env["COFFER_MIGRATION_DATABASE_URL"] = "postgres://owner@db.internal:5432/coffer?sslmode=require"
	cfg, err = LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom with explicit URLs: %v", err)
	}
	if cfg.RuntimeURL() != env["DATABASE_URL"] {
		t.Errorf("RuntimeURL = %q, want the DATABASE_URL override", cfg.RuntimeURL())
	}
	if cfg.MigrationURL() != env["COFFER_MIGRATION_DATABASE_URL"] {
		t.Errorf("MigrationURL = %q, want the COFFER_MIGRATION_DATABASE_URL override", cfg.MigrationURL())
	}
	if cfg.DB.Database != "coffer" {
		t.Errorf("Database = %q, want coffer from the URL path", cfg.DB.Database)
	}
}

func TestBadDatabaseURLIsRejected(t *testing.T) {
	for _, value := range []string{
		"mysql://user@host/db",
		"postgres://",
		"://nonsense",
	} {
		env := baseEnv()
		env["DATABASE_URL"] = value
		if _, err := LoadFrom(lookupFrom(env)); err == nil {
			t.Errorf("LoadFrom accepted DATABASE_URL %q", value)
		}
	}
}

func TestPasswordWithSpecialCharactersIsEscaped(t *testing.T) {
	env := baseEnv()
	env["POSTGRES_PASSWORD"] = "p@ss/word:with?specials"
	env["COFFER_APP_DB_PASSWORD"] = "app@ss/word:with?specials"

	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	// The URL must round-trip: a raw '@' or '/' in the password would corrupt it.
	if !strings.Contains(cfg.MigrationURL(), "%40") && !strings.Contains(cfg.MigrationURL(), "%2F") {
		t.Errorf("the owner password was not escaped in the URL: %s", cfg.MigrationURL())
	}
	if !strings.Contains(cfg.RuntimeURL(), "%40") && !strings.Contains(cfg.RuntimeURL(), "%2F") {
		t.Errorf("the app password was not escaped in the URL: %s", cfg.RuntimeURL())
	}
}

func TestBindAddrValidation(t *testing.T) {
	env := baseEnv()
	env["COFFER_BIND_ADDR"] = "0.0.0.0"
	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.IsLoopback() {
		t.Error("IsLoopback() = true for 0.0.0.0")
	}

	env["COFFER_BIND_ADDR"] = "not-an-address"
	if _, err := LoadFrom(lookupFrom(env)); err == nil {
		t.Error("LoadFrom accepted a bind address that is not an IP")
	}
}

func TestEnvironmentValidation(t *testing.T) {
	env := baseEnv()
	env["COFFER_ENV"] = "staging"
	if _, err := LoadFrom(lookupFrom(env)); err == nil {
		t.Error("LoadFrom accepted an unknown COFFER_ENV")
	}
}

func TestPortValidation(t *testing.T) {
	for _, value := range []string{"0", "65536", "-1", "not-a-number"} {
		env := baseEnv()
		env["COFFER_PORT"] = value
		if _, err := LoadFrom(lookupFrom(env)); err == nil {
			t.Errorf("LoadFrom accepted COFFER_PORT=%q", value)
		}
	}
}

func TestPreviousMasterKey(t *testing.T) {
	env := baseEnv()
	env["COFFER_MASTER_KEY_PREVIOUS"] = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))

	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if len(cfg.MasterKeyPrevious) != MasterKeyLen {
		t.Errorf("MasterKeyPrevious length = %d, want %d", len(cfg.MasterKeyPrevious), MasterKeyLen)
	}

	// Equal to the current key is a misconfiguration, not a rotation.
	env["COFFER_MASTER_KEY_PREVIOUS"] = env["COFFER_MASTER_KEY"]
	if _, err := LoadFrom(lookupFrom(env)); err == nil {
		t.Error("LoadFrom accepted a previous key equal to the current key")
	}
}

func TestRequiredErrorNamesVariableForMasterKey(t *testing.T) {
	env := baseEnv()
	env["COFFER_MASTER_KEY"] = ""

	_, err := LoadFrom(lookupFrom(env))
	if err == nil {
		t.Fatal("LoadFrom accepted an empty master key")
	}
	if !strings.Contains(err.Error(), "COFFER_MASTER_KEY") {
		t.Errorf("error %q does not name COFFER_MASTER_KEY", err)
	}
}

// TestPoolSizing pins the runtime pool bounds.
//
// pgxpool's default is max(4, NumCPU), which is 16 on a 16-core host and leaves the
// documented 50-concurrent-read target queueing on the pool. The ceiling is explicit,
// derived, and bounded: an unbounded pool turns a load spike into "too many clients
// already" against a shared database whose max_connections defaults to 100.
func TestPoolSizing(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := LoadFrom(lookupFrom(baseEnv()))
		if err != nil {
			t.Fatalf("LoadFrom: %v", err)
		}
		if got := cfg.DBMaxConns(); got != DefaultMaxConns {
			t.Errorf("DBMaxConns() = %d, want %d", got, DefaultMaxConns)
		}
		if got := cfg.DBMinConns(); got != DefaultMinConns {
			t.Errorf("DBMinConns() = %d, want %d", got, DefaultMinConns)
		}
		if DefaultMaxConns < 32 {
			t.Errorf("DefaultMaxConns = %d, want at least 32 to cover 50 concurrent reads", DefaultMaxConns)
		}
		// Bounded: two processes must stay inside a default max_connections of 100.
		if 2*DefaultMaxConns > 100 {
			t.Errorf("2*DefaultMaxConns = %d exceeds a default max_connections of 100", 2*DefaultMaxConns)
		}
	})

	t.Run("override", func(t *testing.T) {
		env := baseEnv()
		env["COFFER_DB_MAX_CONNS"] = "64"
		env["COFFER_DB_MIN_CONNS"] = "8"
		cfg, err := LoadFrom(lookupFrom(env))
		if err != nil {
			t.Fatalf("LoadFrom: %v", err)
		}
		if got := cfg.DBMaxConns(); got != 64 {
			t.Errorf("DBMaxConns() = %d, want 64", got)
		}
		if got := cfg.DBMinConns(); got != 8 {
			t.Errorf("DBMinConns() = %d, want 8", got)
		}
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, value := range []string{"0", "-1", "501", "lots"} {
			env := baseEnv()
			env["COFFER_DB_MAX_CONNS"] = value
			if _, err := LoadFrom(lookupFrom(env)); err == nil {
				t.Errorf("LoadFrom accepted COFFER_DB_MAX_CONNS=%q", value)
			}
		}
	})
}
