//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestQuickstartCLI follows the README quickstart through the CLI binary
// (SPEC §6 README, §7.1).
func TestQuickstartCLI(t *testing.T) {
	t.Parallel()
	c := newCLIEnv(t)
	slug := "e2e-qs-" + rnd(4)
	owner := "e2e-owner@" + slug + ".test"

	r := c.want(t, 0, []byte(adminPass+"\n"), "login", "--email", adminEmail)
	if !strings.Contains(string(r.Stdout), adminEmail) {
		t.Errorf("login output should name the user: %s", r)
	}
	// SPEC §7.1: config dir 0700, file 0600.
	dir := filepath.Join(c.CfgHome, "coffer")
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("config dir mode: %v %v", st.Mode().Perm(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Fatalf("no config file written in %s", dir)
	}
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("config file %s mode %v, want 0600", e.Name(), info.Mode().Perm())
		}
	}

	c.want(t, 0, []byte(testPassword+"\n"), "admin", "org", "create", slug, "--owner-email", owner)
	r = c.want(t, 0, nil, "admin", "org", "list", "--json")
	var orgs []map[string]any
	if err := json.Unmarshal(r.Stdout, &orgs); err != nil {
		t.Fatalf("admin org list --json is not one JSON document: %v %s", err, r)
	}
	found := false
	for _, o := range orgs {
		if o["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("new org %s missing from admin org list", slug)
	}

	c.want(t, 0, []byte(testPassword+"\r\n"), "login", "--email", owner)
	r = c.want(t, 0, nil, "whoami", "--json")
	var me map[string]any
	if err := json.Unmarshal(r.Stdout, &me); err != nil || me["email"] != owner || me["role"] != "owner" {
		t.Fatalf("whoami --json: %v %s", err, r)
	}
	c.want(t, 0, nil, "project", "create", "web")
	c.want(t, 0, nil, "env", "create", "dev", "-p", "web")
	c.want(t, 0, nil, "secrets", "set", "DATABASE_URL", "postgres://app:pw@db/app", "-p", "web", "-e", "dev")
	r = c.want(t, 0, nil, "secrets", "get", "DATABASE_URL", "-p", "web", "-e", "dev")
	if string(r.Stdout) != "postgres://app:pw@db/app" {
		t.Fatalf("secrets get output %q, want exact value without newline", r.Stdout)
	}

	// SPEC §4: no plaintext in the CLI config except the CLI's own token.
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(b), testPassword) || strings.Contains(string(b), adminPass) ||
			strings.Contains(string(b), "postgres://app:pw") {
			t.Errorf("config file %s contains a password or secret value", e.Name())
		}
	}

	// Flags in --flag=value form and global flags anywhere (SPEC §7.1).
	r = c.want(t, 0, nil, "--json", "secrets", "list", "--project=web", "--env=dev")
	var list []map[string]any
	if err := json.Unmarshal(r.Stdout, &list); err != nil || len(list) != 1 || list[0]["key"] != "DATABASE_URL" {
		t.Fatalf("secrets list --json: %v %s", err, r)
	}
	if _, has := list[0]["value"]; has {
		t.Errorf("secrets list must never include values: %s", r.Stdout)
	}

	// Logout revokes the PAT server-side (SPEC §4 tokens).
	cfg, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	var conf struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(cfg, &conf)
	c.want(t, 0, nil, "logout")
	if conf.Token != "" {
		must(t, 401, api(t, "GET", "/me", conf.Token, nil), "PAT after logout")
	} else {
		t.Errorf("could not read token from config.json to check server-side revocation")
	}
	c.want(t, 3, nil, "whoami")

	// Passwords never in argv: there is no --password flag.
	r = c.run(t, nil, "login", "--email", owner, "--password", testPassword)
	if r.Code != 2 {
		t.Errorf("login --password must be a usage error (exit 2): %s", r)
	}
}

// TestCLITokenOverride checks COFFER_TOKEN: config file neither read nor written.
func TestCLITokenOverride(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "tokov")
	o.project(t, "app", map[string]bool{"dev": false})
	setSecret(t, o.Owner.Token, "app", "dev", "K", "v")

	c := newCLIEnv(t)
	c.Token = o.Owner.Token
	r := c.want(t, 0, nil, "secrets", "get", "K", "-p", "app", "-e", "dev")
	if string(r.Stdout) != "v" {
		t.Fatalf("get via COFFER_TOKEN: %s", r)
	}
	if r := c.run(t, []byte(testPassword+"\n"), "login", "--email", o.Owner.Email); r.Code != 2 {
		t.Errorf("login with COFFER_TOKEN set: want exit 2, got %s", r)
	}
	if _, err := os.Stat(filepath.Join(c.CfgHome, "coffer")); err == nil {
		entries, _ := os.ReadDir(filepath.Join(c.CfgHome, "coffer"))
		if len(entries) > 0 {
			t.Errorf("config written although COFFER_TOKEN is set: %v", entries)
		}
	}
	// A bogus token gives exit 3, and the token is not echoed in errors.
	c.Token = "cof_pat_" + rnd(32)
	r = c.want(t, 3, nil, "whoami")
	if strings.Contains(string(r.Stderr)+string(r.Stdout), c.Token) {
		t.Errorf("token echoed in CLI output: %s", r)
	}
	// Usage errors exit 2.
	c.Token = o.Owner.Token
	c.want(t, 2, nil, "secrets", "get", "-p", "app", "-e", "dev")
	c.want(t, 2, nil, "secrets", "get", "K", "-p", "app", "-e", "dev", "--bogus-flag")
	c.want(t, 2, nil, "nosuchcommand")
}
