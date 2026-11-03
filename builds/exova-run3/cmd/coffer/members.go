package main

import (
	"fmt"
	"net/http"
	"strings"
)

// cmdMember dispatches `coffer member ...` (SPEC §7.1).
func (c *cli) cmdMember(args []string) error {
	if len(args) == 0 {
		return usagef("missing member command: expected `coffer member add|list|role|remove`")
	}
	switch args[0] {
	case "add":
		return c.cmdMemberAdd(args[1:])
	case "list", "ls":
		return c.cmdMemberList(args[1:])
	case "role":
		return c.cmdMemberRole(args[1:])
	case "remove", "rm":
		return c.cmdMemberRemove(args[1:])
	default:
		return usagef("unknown member command %q: expected `coffer member add|list|role|remove`", args[0])
	}
}

// cmdMemberAdd implements `coffer member add EMAIL --role R`, with the initial
// password on stdin.
func (c *cli) cmdMemberAdd(args []string) error {
	fs := newFlagSet("member add")
	var role stringOpt
	fs.Var(&role, "role", "member, admin or owner")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "member add EMAIL --role member|admin|owner"); err != nil {
		return err
	}
	email := fs.Arg(0)
	if err := validateEmail(email); err != nil {
		return err
	}
	if _, err := requiredString(fs, &role, "--role", "member add EMAIL --role member|admin|owner"); err != nil {
		return err
	}
	if err := validateRole(role.value); err != nil {
		return err
	}
	password, err := c.in.password("initial password")
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	body := map[string]string{"email": email, "role": role.value, "password": password}
	resp, err := cl.raw(http.MethodPost, "/api/v1/members", nil, body)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Added %s as %s\n", email, role.value)
	return nil
}

// cmdMemberList implements `coffer member list`.
func (c *cli) cmdMemberList(args []string) error {
	fs := newFlagSet("member list")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "member list"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/members", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []memberRow
	if err := decodeList(resp.body, "members", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		note := ""
		if r.MustChangePassword {
			note = "password change required"
		}
		table = append(table, []string{r.Email, r.Role, r.ID, r.CreatedAt.String(), note})
	}
	return c.table([]string{"EMAIL", "ROLE", "ID", "CREATED", "NOTE"}, table)
}

// cmdMemberRole implements `coffer member role EMAIL ROLE`.
func (c *cli) cmdMemberRole(args []string) error {
	fs := newFlagSet("member role")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 2, "member role EMAIL member|admin|owner"); err != nil {
		return err
	}
	email := fs.Arg(0)
	if err := validateEmail(email); err != nil {
		return err
	}
	role := fs.Arg(1)
	if err := validateRole(role); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	id, err := c.resolveMemberID(cl, email)
	if err != nil {
		return err
	}
	body := map[string]string{"role": role}
	path := "/api/v1/members/" + escapePath(id)
	resp, err := cl.raw(http.MethodPatch, path, nil, body)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Set role of %s to %s\n", email, role)
	return nil
}

// cmdMemberRemove implements `coffer member remove EMAIL`.
func (c *cli) cmdMemberRemove(args []string) error {
	fs := newFlagSet("member remove")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "member remove EMAIL"); err != nil {
		return err
	}
	email := fs.Arg(0)
	if err := validateEmail(email); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	id, err := c.resolveMemberID(cl, email)
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodDelete, "/api/v1/members/"+escapePath(id), nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Removed %s\n", email)
	return nil
}

// cmdGrant dispatches `coffer grant ...`.
func (c *cli) cmdGrant(args []string) error {
	if len(args) == 0 {
		return usagef("missing grant command: expected `coffer grant set|revoke`")
	}
	switch args[0] {
	case "set":
		return c.cmdGrantSet(args[1:])
	case "revoke", "rm", "delete":
		return c.cmdGrantRevoke(args[1:])
	default:
		return usagef("unknown grant command %q: expected `coffer grant set|revoke`", args[0])
	}
}

// cmdGrantSet implements
// `coffer grant set EMAIL -p PROJECT --level viewer|reader|writer`.
func (c *cli) cmdGrantSet(args []string) error {
	fs := newFlagSet("grant set")
	var scope secretScope
	var level stringOpt
	scope.register(fs)
	fs.Var(&level, "level", "viewer, reader or writer")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "grant set EMAIL -p PROJECT --level viewer|reader|writer"); err != nil {
		return err
	}
	email := fs.Arg(0)
	if err := validateEmail(email); err != nil {
		return err
	}
	if _, err := requiredString(fs, &level, "--level", "grant set EMAIL -p PROJECT --level viewer|reader|writer"); err != nil {
		return err
	}
	if err := validateLevel(level.value); err != nil {
		return err
	}
	project, err := scope.requireProject("grant set EMAIL -p PROJECT --level viewer|reader|writer")
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	id, err := c.resolveMemberID(cl, email)
	if err != nil {
		return err
	}
	body := map[string]string{"level": level.value}
	path := "/api/v1/members/" + escapePath(id) + "/grants/" + escapePath(project)
	resp, err := cl.raw(http.MethodPut, path, nil, body)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Granted %s on %s to %s\n", level.value, project, email)
	return nil
}

// cmdGrantRevoke implements `coffer grant revoke EMAIL -p PROJECT`.
func (c *cli) cmdGrantRevoke(args []string) error {
	fs := newFlagSet("grant revoke")
	var scope secretScope
	scope.register(fs)
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "grant revoke EMAIL -p PROJECT"); err != nil {
		return err
	}
	email := fs.Arg(0)
	if err := validateEmail(email); err != nil {
		return err
	}
	project, err := scope.requireProject("grant revoke EMAIL -p PROJECT")
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	id, err := c.resolveMemberID(cl, email)
	if err != nil {
		return err
	}
	path := "/api/v1/members/" + escapePath(id) + "/grants/" + escapePath(project)
	resp, err := cl.raw(http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Revoked %s's grant on %s\n", email, project)
	return nil
}

// resolveMemberID maps an email onto the member's opaque user id, which is what
// the member and grant routes address. A missing member is exit 5, decided from
// a successful listing.
func (c *cli) resolveMemberID(cl *client, email string) (string, error) {
	resp, err := cl.raw(http.MethodGet, "/api/v1/members", nil, nil)
	if err != nil {
		return "", err
	}
	var rows []memberRow
	if err := decodeList(resp.body, "members", &rows); err != nil {
		return "", fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	for _, r := range rows {
		if strings.EqualFold(r.Email, email) {
			if r.ID == "" {
				return "", fmt.Errorf("member %s has no id in the server response", email)
			}
			return r.ID, nil
		}
	}
	return "", &exitError{code: exitNotFound, msg: fmt.Sprintf("no member with email %s", email)}
}
