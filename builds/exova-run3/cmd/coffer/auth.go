package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// cmdLogin implements `coffer login --email EMAIL [--url URL]`. The password is
// read from stdin as one line and never appears in argv (SPEC §4).
func (c *cli) cmdLogin(args []string) error {
	fs := newFlagSet("login")
	var email stringOpt
	fs.Var(&email, "email", "email address")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "login --email EMAIL [--url URL]"); err != nil {
		return err
	}
	if err := validateEmail(email.value); err != nil {
		return err
	}
	password, err := c.in.password("password")
	if err != nil {
		return err
	}

	// A token-less client: login is authenticated by the password in the body,
	// never by a credential left over from a previous session. A stale PAT would
	// otherwise be rejected by the auth middleware before the handler ever reads
	// the password, which is unrecoverable without deleting the config by hand.
	cl, err := c.anonymousClient()
	if err != nil {
		return err
	}
	var out loginResponse
	body := map[string]string{"email": email.value, "password": password}
	if err := cl.sendJSON(http.MethodPost, "/api/v1/auth/token", nil, body, &out); err != nil {
		return err
	}
	if out.Token == "" {
		return errors.New("the server returned no token")
	}

	// Persist the URL that worked and the PAT. With COFFER_TOKEN set this is a
	// no-op: no config file is read or written in that mode.
	cfg, err := c.config()
	if err != nil {
		return err
	}
	cfg.URL = cl.base
	cfg.Token = out.Token
	if err := cfg.save(); err != nil {
		return err
	}

	if c.json {
		return c.printJSON(loginJSON(out))
	}
	fmt.Fprintf(c.stdout, "Logged in as %s\n", loginEmail(out))
	if out.User != nil && out.User.MustChangePassword {
		fmt.Fprintln(c.stdout, "Your password must be changed before you can use the service: run `coffer passwd`.")
	}
	return nil
}

// cmdLogout implements `coffer logout`: revoke the PAT on the server, then drop
// it locally. A 401 means it is already dead, which still leaves the caller
// logged out.
func (c *cli) cmdLogout(args []string) error {
	fs := newFlagSet("logout")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "logout"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		// Nothing to revoke locally either, but clear anything stale.
		if errors.Is(err, errNotLoggedIn) {
			if cfg, cfgErr := c.config(); cfgErr == nil && !cfg.envToken && cfg.Token != "" {
				_ = cfg.clear()
			}
		}
		return err
	}
	var out map[string]any
	err = cl.sendJSON(http.MethodPost, "/api/v1/auth/logout", nil, nil, &out)
	var apiErr *apiError
	if err != nil && (!errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized) {
		return err
	}

	cfg, cfgErr := c.config()
	if cfgErr != nil {
		return cfgErr
	}
	if cfg.envToken {
		// The credential came from the environment; the file is untouched.
		if c.json {
			return c.printJSON(map[string]any{"status": "logged_out"})
		}
		fmt.Fprintln(c.stdout, "Logged out. COFFER_TOKEN is set in the environment and was not changed.")
		return nil
	}
	if err := cfg.clear(); err != nil {
		return err
	}
	if c.json {
		return c.printJSON(map[string]any{"status": "logged_out"})
	}
	fmt.Fprintln(c.stdout, "Logged out.")
	return nil
}

// cmdWhoami implements `coffer whoami`.
func (c *cli) cmdWhoami(args []string) error {
	fs := newFlagSet("whoami")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "whoami"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	var body []byte
	resp, err := cl.raw(http.MethodGet, "/api/v1/me", nil, nil)
	if err != nil {
		// A service token is a valid credential, so /me refuses it with 403 rather
		// than 401 (SPEC §2.7: a service token performs secret operations inside
		// its scope, and /me is not one). The generic "you may lack permission"
		// hint is wrong here — nothing is wrong with the token. The cof_st_ prefix
		// identifies the case without a second request.
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden && strings.HasPrefix(cl.token, "cof_st_") {
			apiErr.Hint = "this is a service token: it has no user identity and is scoped to one project and environment. " +
				"Use a personal access token from `coffer login` for commands outside its scope"
		}
		return err
	}
	body = resp.body
	var me meResponse
	if err := decodeObject(body, "me", &me); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	if c.json {
		return c.printJSONBytes(body)
	}
	switch {
	case me.Role == "service_token" && me.Token != nil:
		fmt.Fprintf(c.stdout, "service token %s\n", orDash(me.Token.ID))
		fmt.Fprintf(c.stdout, "  project: %s\n  environment: %s\n  access: %s\n  expires: %s\n",
			orDash(me.Token.Project), orDash(me.Token.Env), orDash(me.Token.Access), me.Token.ExpiresAt.String())
	case me.User != nil:
		fmt.Fprintf(c.stdout, "%s\n", orDash(me.User.Email))
		fmt.Fprintf(c.stdout, "  role: %s\n", orDash(firstNonEmpty(me.Role, me.User.Role)))
		org := "-"
		if me.Organization != nil {
			org = orDash(me.Organization.Slug)
		} else if me.User.Organization != nil {
			org = orDash(me.User.Organization.Slug)
		}
		fmt.Fprintf(c.stdout, "  organization: %s\n", org)
		fmt.Fprintf(c.stdout, "  user id: %s\n", orDash(me.User.ID))
		if me.User.MustChangePassword {
			fmt.Fprintln(c.stdout, "  password change required: run `coffer passwd`")
		}
	default:
		fmt.Fprintf(c.stdout, "role: %s\n", orDash(me.Role))
	}
	return nil
}

// cmdPasswd implements `coffer passwd`: stdin carries the current password on
// one line and the new password on the next (SPEC §7.1).
func (c *cli) cmdPasswd(args []string) error {
	fs := newFlagSet("passwd")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "passwd"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	current, err := c.in.password("current password")
	if err != nil {
		return err
	}
	next, err := c.in.password("new password")
	if err != nil {
		return err
	}
	if len(next) < 12 {
		return usagef("the new password must be at least 12 characters")
	}
	body := map[string]string{"current_password": current, "new_password": next}
	var out map[string]any
	if err := cl.sendJSON(http.MethodPost, "/api/v1/auth/password", nil, body, &out); err != nil {
		// A wrong current password comes back as 400 validation_error, not 401:
		// the PAT resolved fine, so it is a payload error (authapi handlers_auth.go
		// and docs/SLICE-AUTH.md decision 5). The hint says so, because the generic
		// validation text does not tell the caller what to do next.
		//
		// A 401 on this route really does mean the credential is dead, so it keeps
		// the generic "run coffer login" hint untouched.
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
			// Only add the hint when the server's own message does not already say
			// it, so the caller never reads the same sentence twice.
			if !strings.Contains(strings.ToLower(apiErr.Message), "current password") {
				apiErr.Hint = "the current password is incorrect; nothing was changed"
			}
		}
		return err
	}
	if c.json {
		return c.printJSON(map[string]any{"status": "password_changed"})
	}
	fmt.Fprintln(c.stdout, "Password changed.")
	return nil
}

// loginJSON is the --json document for a successful login. The token is
// included because the caller just authenticated for it, exactly as the server
// returns it once.
func loginJSON(out loginResponse) map[string]any {
	doc := map[string]any{"token": out.Token}
	if out.User != nil {
		doc["user"] = out.User
	}
	return doc
}

func loginEmail(out loginResponse) string {
	if out.User != nil && out.User.Email != "" {
		return out.User.Email
	}
	return "the server"
}
