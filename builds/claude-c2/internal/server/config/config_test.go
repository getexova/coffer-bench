package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{
		"COFFER_MASTER_KEY":               base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "admin@example.com",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "a-long-enough-password",
		"POSTGRES_USER":                   "coffer",
		"POSTGRES_PASSWORD":               "pw",
		"POSTGRES_DB":                     "coffer",
	}
}

func TestMissingRequired(t *testing.T) {
	for _, name := range []string{"COFFER_MASTER_KEY", "COFFER_BOOTSTRAP_ADMIN_EMAIL", "COFFER_BOOTSTRAP_ADMIN_PASSWORD", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"} {
		m := base()
		delete(m, name)
		_, err := Load(env(m))
		if err == nil || err.Error() != "config error: missing required environment variable "+name {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// COFFER_DATABASE_URL replaces the POSTGRES_* requirement.
	m := base()
	delete(m, "POSTGRES_USER")
	m["COFFER_DATABASE_URL"] = "postgres://x@y/z"
	if _, err := Load(env(m)); err != nil {
		t.Fatal(err)
	}
}

func TestMasterKeyValidation(t *testing.T) {
	bad := []string{
		PlaceholderMasterKey,
		base64.StdEncoding.EncodeToString(make([]byte, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"not base64 !!!",
	}
	for _, k := range bad {
		m := base()
		m["COFFER_MASTER_KEY"] = k
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "COFFER_MASTER_KEY") {
			t.Errorf("accepted %q: %v", k, err)
		}
		m = base()
		m["COFFER_MASTER_KEY_PREVIOUS"] = k
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "COFFER_MASTER_KEY_PREVIOUS") {
			t.Errorf("previous accepted %q: %v", k, err)
		}
	}
	raw := make([]byte, 32)
	raw[0] = 0xfb
	raw[1] = 0xff
	for _, k := range []string{base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)} {
		got, err := ParseMasterKey(k)
		if err != nil || len(got) != 32 || got[0] != 0xfb {
			t.Errorf("rejected %q: %v", k, err)
		}
	}
}

func TestDefaultsAndDSN(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8420" || c.Argon2MemoryKiB != 65536 || c.PATTTL.Hours() != 720 || c.TrustProxy || c.AppRole != "coffer_app" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.DatabaseURL != "postgres://coffer:pw@db:5432/coffer?sslmode=disable" {
		t.Fatalf("dsn %q", c.DatabaseURL)
	}
	m := base()
	m["COFFER_ARGON2_MEMORY_KIB"] = "1024"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("accepted low argon memory")
	}
	m = base()
	m["COFFER_BOOTSTRAP_ADMIN_PASSWORD"] = "short"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("accepted short bootstrap password")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPassword("12345678901") == nil {
		t.Fatal("11 chars accepted")
	}
	if CheckPassword("123456789012") != nil {
		t.Fatal("12 chars rejected")
	}
	if CheckPassword("ééééééééééé") == nil { // 11 runes, 22 bytes
		t.Fatal("11 runes accepted")
	}
	if CheckPassword(strings.Repeat("a", 1025)) == nil {
		t.Fatal("1025 bytes accepted")
	}
	if CheckPassword("aaaaaaaaaaaa\xff") == nil {
		t.Fatal("invalid utf8 accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	if n, ok := NormalizeEmail("  Alice@Example.COM "); !ok || n != "alice@example.com" {
		t.Fatal(n, ok)
	}
	for _, bad := range []string{"", "a", "@b", "a@", "a@b@c", "a b@c", "a@b\nc"} {
		if _, ok := NormalizeEmail(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
