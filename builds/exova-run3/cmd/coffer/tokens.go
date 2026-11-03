package main

import (
	"fmt"
	"net/http"
)

// cmdToken dispatches `coffer token ...` (SPEC §7.1).
func (c *cli) cmdToken(args []string) error {
	if len(args) == 0 {
		return usagef("missing token command: expected `coffer token create|list|revoke`")
	}
	switch args[0] {
	case "create":
		return c.cmdTokenCreate(args[1:])
	case "list", "ls":
		return c.cmdTokenList(args[1:])
	case "revoke", "rm", "delete":
		return c.cmdTokenRevoke(args[1:])
	default:
		return usagef("unknown token command %q: expected `coffer token create|list|revoke`", args[0])
	}
}

// cmdTokenCreate implements
// `coffer token create -p P -e E --access read|read-write --ttl DURATION [--name NAME]`.
// The token is printed once, at creation, and never listed afterwards.
func (c *cli) cmdTokenCreate(args []string) error {
	const synopsis = "token create -p P -e E --access read|read-write --ttl DURATION [--name NAME]"
	fs := newFlagSet("token create")
	var scope secretScope
	var access, ttl, name stringOpt
	scope.register(fs)
	fs.Var(&access, "access", "read or read-write")
	fs.Var(&ttl, "ttl", "duration such as 30m, 12h or 7d (1m..90d)")
	fs.Var(&name, "name", "a label for the token")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, synopsis); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	if _, err := requiredString(fs, &access, "--access", synopsis); err != nil {
		return err
	}
	if err := validateAccess(access.value); err != nil {
		return err
	}
	ttlSeconds, err := parseTTL(ttl.value)
	if err != nil {
		return err
	}

	body := map[string]any{
		"project":     project,
		"env":         env,
		"access":      access.value,
		"ttl_seconds": ttlSeconds,
	}
	if name.value != "" {
		body["name"] = name.value
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	var created tokenCreated
	if err := cl.sendJSON(http.MethodPost, "/api/v1/tokens", nil, body, &created); err != nil {
		return err
	}
	if created.Token == "" {
		return fmt.Errorf("the server returned no token")
	}
	if c.json {
		return c.printJSON(map[string]any{"id": created.ID, "token": created.Token})
	}
	// The token is the only thing a script needs on stdout.
	fmt.Fprintln(c.stdout, created.Token)
	fmt.Fprintf(c.stderr, "Created service token %s (%s on %s/%s, expires in %s). It is shown once and cannot be retrieved again.\n",
		orDash(created.ID), access.value, project, env, ttl.value)
	return nil
}

// cmdTokenList implements `coffer token list`.
func (c *cli) cmdTokenList(args []string) error {
	fs := newFlagSet("token list")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "token list"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/tokens", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []tokenRow
	if err := decodeList(resp.body, "tokens", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		status := "active"
		if r.RevokedAt.set {
			status = "revoked"
		}
		table = append(table, []string{
			r.ID,
			orDash(r.Name),
			orDash(r.Project) + "/" + orDash(r.Env),
			orDash(r.Access),
			r.ExpiresAt.String(),
			status,
		})
	}
	return c.table([]string{"ID", "NAME", "SCOPE", "ACCESS", "EXPIRES", "STATUS"}, table)
}

// cmdTokenRevoke implements `coffer token revoke ID`.
func (c *cli) cmdTokenRevoke(args []string) error {
	fs := newFlagSet("token revoke")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "token revoke ID"); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return usagef("missing token ID: expected `coffer token revoke ID`")
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodDelete, "/api/v1/tokens/"+escapePath(id), nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		if len(resp.body) == 0 {
			return c.printJSON(map[string]any{"status": "revoked", "id": id})
		}
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Revoked token %s\n", id)
	return nil
}
