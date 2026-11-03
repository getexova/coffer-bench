package cli

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func cmdLogin(c *ctx) error {
	a := c.app
	if _, ok := a.envToken(); ok {
		return usageErr("", "COFFER_TOKEN is set; unset it to use `coffer login` (the config file is not used while COFFER_TOKEN is set)")
	}
	email := c.flag("email")
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	base, err := a.resolveURL(c.flag("url"), cfg)
	if err != nil {
		return err
	}
	warnPlainHTTP(c, base)
	password, err := a.readPassword("Password: ")
	if err != nil {
		return err
	}
	cl := a.makeClient(base, "")
	resp, err := cl.do("POST", "/auth/token", nil, map[string]string{"email": email, "password": password})
	if err != nil {
		return err
	}
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	token := str(m, "token")
	if !strings.HasPrefix(token, "cof_pat_") || !validTokenChars(token) {
		return genericErr("unexpected response from server")
	}
	cfg.URL = base
	cfg.Token = token
	if err := a.saveConfig(cfg); err != nil {
		return err
	}
	delete(m, "token")
	if c.json() {
		return writeJSON(c.out(), m)
	}
	shown := email
	if u, ok := m["user"].(map[string]any); ok && str(u, "email") != "" {
		shown = str(u, "email")
	}
	fmt.Fprintf(c.out(), "logged in as %s\n", sanitize(shown))
	return nil
}

// warnPlainHTTP warns when credentials would cross a network in cleartext.
func warnPlainHTTP(c *ctx, base string) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" {
		return
	}
	h := u.Hostname()
	if h == "localhost" {
		return
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return
	}
	fmt.Fprintf(c.app.Stderr, "warning: %s uses plain HTTP; credentials are sent unencrypted\n", base)
}

func cmdLogout(c *ctx) error {
	a := c.app
	if _, fromEnv := a.envToken(); fromEnv {
		cl, err := c.newClient(true)
		if err != nil {
			return err
		}
		if _, err := cl.do("POST", "/auth/logout", nil, nil); err != nil {
			return err
		}
		return logoutOutput(c, "logged out")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return logoutOutput(c, "not logged in")
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	_, callErr := cl.do("POST", "/auth/logout", nil, nil)
	if callErr != nil {
		ce, ok := callErr.(*cliError)
		if !ok || ce.code != ExitUnauth {
			// The server may not have revoked the token; keep it so the
			// user can retry rather than silently leaving it valid.
			return callErr
		}
	}
	cfg.Token = ""
	if err := a.saveConfig(cfg); err != nil {
		return err
	}
	return logoutOutput(c, "logged out")
}

func logoutOutput(c *ctx, msg string) error {
	if c.json() {
		status := "logged_out"
		if msg == "not logged in" {
			status = "not_logged_in"
		}
		return writeJSON(c.out(), map[string]string{"status": status})
	}
	fmt.Fprintln(c.out(), msg)
	return nil
}

func cmdWhoami(c *ctx) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("GET", "/me", nil, nil)
	if err != nil {
		return err
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	if str(m, "type") == "service_token" {
		printKV(c.out(), m, []string{"type", "id", "org_id", "project", "env", "access", "expires_at"})
		return nil
	}
	printKV(c.out(), m, []string{"type", "id", "email", "role", "org_id", "org_slug", "must_change_password"})
	return nil
}

func cmdPasswd(c *ctx) error {
	a := c.app
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	cur, err := a.readPassword("Current password: ")
	if err != nil {
		return err
	}
	next, err := a.readPassword("New password: ")
	if err != nil {
		return err
	}
	resp, err := cl.do("POST", "/auth/password", nil, map[string]string{"current_password": cur, "new_password": next})
	if err != nil {
		return err
	}
	if c.json() {
		return printJSONOr(c, resp, map[string]string{"status": "password_changed"})
	}
	fmt.Fprintln(c.out(), "password changed")
	return nil
}

// printJSONOr prints the server JSON body, or fallback if the body is empty.
func printJSONOr(c *ctx, resp *response, fallback any) error {
	if len(strings.TrimSpace(string(resp.body))) == 0 {
		return writeJSON(c.out(), fallback)
	}
	return printRawJSON(c.out(), resp.body)
}
