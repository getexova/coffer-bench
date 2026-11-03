package idgen

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	id := New("prj_")
	if !strings.HasPrefix(id, "prj_") {
		t.Errorf("New(\"prj_\") = %q, want the prefix", id)
	}
	// 12 random bytes as hex is 24 characters.
	if got := len(id) - len("prj_"); got != 24 {
		t.Errorf("id body length = %d, want 24 hex characters", got)
	}
}

func TestNewIsUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := New("")
		if seen[id] {
			t.Fatalf("New returned a duplicate id after %d draws: %q", i, id)
		}
		seen[id] = true
	}
}

func TestSecret(t *testing.T) {
	for _, prefix := range []string{PrefixPAT, PrefixService} {
		token := Secret(prefix)
		if !strings.HasPrefix(token, prefix) {
			t.Errorf("Secret(%q) = %q, want the prefix", prefix, token)
		}
		// 32 random bytes as hex is 64 characters, so 256 bits of entropy.
		if got := len(token) - len(prefix); got != 64 {
			t.Errorf("token body length = %d, want 64 hex characters", got)
		}
	}
}

func TestSecretIsUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		token := Secret(PrefixPAT)
		if seen[token] {
			t.Fatalf("Secret returned a duplicate token after %d draws", i)
		}
		seen[token] = true
	}
}

func TestPrefixes(t *testing.T) {
	// The prefixes are part of the frozen token format.
	if PrefixPAT != "cof_pat_" {
		t.Errorf("PrefixPAT = %q, want cof_pat_", PrefixPAT)
	}
	if PrefixService != "cof_st_" {
		t.Errorf("PrefixService = %q, want cof_st_", PrefixService)
	}
}

func TestHexOnly(t *testing.T) {
	for _, value := range []string{New("x_"), Secret(PrefixPAT)} {
		body := strings.TrimPrefix(strings.TrimPrefix(value, "x_"), PrefixPAT)
		for _, c := range body {
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'f':
			default:
				t.Errorf("id %q contains a non-hex character %q", value, c)
			}
		}
	}
}
