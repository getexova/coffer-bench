//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCLICommands drives the remaining §7.1 commands and their exit codes.
func TestCLICommands(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "cli")
	c := newCLIEnv(t)
	c.Token = o.Owner.Token
	email := "e2e-dev-" + rnd(3) + "@" + o.Slug + ".test"

	c.want(t, 0, nil, "project", "create", "web")
	c.want(t, 8, nil, "project", "create", "web")
	c.want(t, 6, nil, "project", "create", "Bad_Slug")
	c.want(t, 0, nil, "env", "create", "prod", "-p", "web", "--protected")
	c.want(t, 0, nil, "env", "create", "dev", "--project=web")
	c.want(t, 5, nil, "env", "create", "dev", "-p", "nope")
	var envs []map[string]any
	if err := json.Unmarshal(c.want(t, 0, nil, "env", "list", "-p", "web", "--json").Stdout, &envs); err != nil || len(envs) != 2 {
		t.Fatalf("env list --json: %v %v", err, envs)
	}
	for _, e := range envs {
		if e["slug"] == "prod" && e["protected"] != true {
			t.Errorf("--protected not applied: %v", e)
		}
	}
	if r := c.want(t, 0, nil, "project", "list"); !strings.Contains(string(r.Stdout), "web") {
		t.Errorf("project list: %s", r)
	}

	c.want(t, 0, []byte(testPassword+"\n"), "member", "add", email, "--role", "member")
	c.want(t, 8, []byte(testPassword+"\n"), "member", "add", email, "--role", "member")
	c.want(t, 6, []byte("short\n"), "member", "add", "e2e-s-"+rnd(3)+"@x.test", "--role", "member")
	c.want(t, 0, nil, "grant", "set", strings.ToUpper(email), "-p", "web", "--level", "reader")
	var members []map[string]any
	if err := json.Unmarshal(c.want(t, 0, nil, "member", "list", "--json").Stdout, &members); err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, m := range members {
		if m["email"] == email {
			gs, _ := m["grants"].([]any)
			ok = len(gs) == 1
		}
	}
	if !ok {
		t.Errorf("member list missing %s with one grant: %v", email, members)
	}
	dev := newCLIEnv(t)
	dev.want(t, 0, []byte(testPassword+"\n"), "login", "--email", email)
	dev.want(t, 4, nil, "member", "list")
	dev.want(t, 4, nil, "token", "list")
	dev.want(t, 4, nil, "audit", "verify")
	dev.want(t, 4, nil, "project", "create", "mine")
	c.want(t, 0, nil, "secrets", "set", "K", "v", "-p", "web", "-e", "dev")
	if r := dev.want(t, 0, nil, "secrets", "get", "K", "-p", "web", "-e", "dev"); string(r.Stdout) != "v" {
		t.Errorf("reader get: %s", r)
	}
	dev.want(t, 4, nil, "secrets", "set", "K", "w", "-p", "web", "-e", "dev")
	// --json errors: stdout stays empty.
	if r := dev.want(t, 4, nil, "secrets", "set", "K", "w", "-p", "web", "-e", "dev", "--json"); len(r.Stdout) != 0 {
		t.Errorf("--json error wrote to stdout: %s", r)
	}
	c.want(t, 0, nil, "member", "role", email, "admin")
	dev.want(t, 0, nil, "member", "list")
	c.want(t, 0, nil, "member", "role", email, "member")
	dev.want(t, 4, nil, "member", "list")
	// Promotion drops grants; demotion must not resurrect old access.
	dev.want(t, 5, nil, "secrets", "get", "K", "-p", "web", "-e", "dev")
	c.want(t, 0, nil, "grant", "set", email, "-p", "web", "--level", "reader")
	dev.want(t, 0, nil, "secrets", "get", "K", "-p", "web", "-e", "dev")
	c.want(t, 0, nil, "grant", "revoke", email, "-p", "web")
	dev.want(t, 5, nil, "secrets", "get", "K", "-p", "web", "-e", "dev")
	c.want(t, 5, nil, "grant", "set", "e2e-nobody-"+rnd(3)+"@x.test", "-p", "web", "--level", "reader")
	c.want(t, 8, nil, "member", "role", o.Owner.Email, "admin")

	// Protected change rejected via CLI by the owner.
	c.want(t, 0, []byte(testPassword+"\n"), "member", "add", "e2e-w-"+rnd(3)+"@"+o.Slug+".test", "--role", "admin")
	r := c.want(t, 7, nil, "secrets", "set", "P", "pv", "-p", "web", "-e", "prod", "--json")
	var pend map[string]any
	_ = json.Unmarshal(r.Stdout, &pend)
	c.want(t, 4, nil, "change", "approve", str(pend, "change_id"))
	c.want(t, 0, nil, "change", "reject", str(pend, "change_id"))
	c.want(t, 8, nil, "change", "reject", str(pend, "change_id"))

	var toks []map[string]any
	c.want(t, 0, nil, "token", "create", "-p", "web", "-e", "dev", "--access", "read", "--ttl", "1h")
	if err := json.Unmarshal(c.want(t, 0, nil, "token", "list", "--json").Stdout, &toks); err != nil || len(toks) != 1 {
		t.Errorf("token list --json: %v %v", err, toks)
	}
	c.want(t, 5, nil, "token", "revoke", "tok_doesnotexist")
	c.want(t, 0, nil, "whoami")

	// Platform admin via CLI: org-scoped commands are 404, admin commands work.
	pa := newCLIEnv(t)
	pa.Token = adminToken(t)
	pa.want(t, 5, nil, "project", "list")
	pa.want(t, 5, nil, "member", "list")
	pa.want(t, 5, nil, "audit", "list")
	pa.want(t, 5, nil, "secrets", "get", "K", "-p", "web", "-e", "dev")
	c.want(t, 5, nil, "admin", "org", "list")
	d := newOrg(t, "clidis")
	pa.want(t, 0, nil, "admin", "org", "disable", d.Slug)
	pa.want(t, 5, nil, "admin", "org", "disable", "e2e-none-"+rnd(4))
	must(t, 401, api(t, "GET", "/me", d.Owner.Token, nil), "disabled org owner")
	pa.want(t, 8, []byte(testPassword+"\n"), "admin", "org", "create", o.Slug, "--owner-email", "e2e-x-"+rnd(3)+"@x.test")
}

// TestRunSignalForwarding: SIGTERM to `coffer run` reaches the child (SPEC §7.1).
func TestRunSignalForwarding(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "sig")
	o.project(t, "app", map[string]bool{"dev": false})
	setSecret(t, o.Owner.Token, "app", "dev", "K", "v")
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		ce := newCLIEnv(t)
		ce.Token = o.Owner.Token
		cmd := exec.Command(cliPath, "run", "-p", "app", "-e", "dev", "--", "sh", "-c",
			`trap 'echo got-signal; exit 42' TERM INT; echo ready; while :; do sleep 0.05; done`)
		cmd.Env = ce.environ()
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var errb bytes.Buffer
		cmd.Stderr = &errb
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(out)
		if !sc.Scan() || sc.Text() != "ready" {
			_ = cmd.Process.Kill()
			t.Fatalf("child did not start: %q %s", sc.Text(), errb.String())
		}
		_ = cmd.Process.Signal(sig)
		done := make(chan error, 1)
		go func() {
			var rest strings.Builder
			for sc.Scan() {
				rest.WriteString(sc.Text())
			}
			if !strings.Contains(rest.String(), "got-signal") {
				t.Errorf("%v not forwarded to child (output %q)", sig, rest.String())
			}
			done <- cmd.Wait()
		}()
		select {
		case err := <-done:
			var ee *exec.ExitError
			if code := 0; err != nil {
				if ok := asExit(err, &ee); ok {
					code = ee.ExitCode()
				}
				if code != 42 {
					t.Errorf("%v: run exit %d, want child's 42", sig, code)
				}
			} else {
				t.Errorf("%v: run exited 0, want 42", sig)
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("%v: run did not exit", sig)
		}
	}
}

func asExit(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// TestPlatformLogRouting: unauthenticated failures go to the platform log (SPEC §4 Audit).
func TestPlatformLogRouting(t *testing.T) {
	t.Parallel()
	ghost := "e2e-ghost-" + rnd(4) + "@nowhere.test"
	must(t, 401, api(t, "POST", "/auth/token", "", map[string]string{"email": ghost, "password": "ghost-password-123"}), "unknown login")
	evs := must(t, 200, api(t, "GET", "/admin/audit?limit=200", adminToken(t), nil), "platform log").arr(t)
	found := false
	for _, e := range evs {
		if str(e, "action") == "auth.login" && str(e, "result") == "failed" {
			found = true
		}
		if strings.Contains(str(e, "target"), ghost) || strings.Contains(fmtJSON(e), "ghost-password-123") {
			t.Errorf("platform log stores the raw email or password: %v", e)
		}
	}
	if !found {
		t.Errorf("failed unknown-email login not in platform log")
	}
	for _, e := range evs {
		if str(e, "action") == "secret.read" {
			t.Errorf("org event leaked into platform log: %v", e)
		}
	}
}

func fmtJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
