package main

import (
	"fmt"
	"net/http"
)

// cmdAdmin dispatches the platform-admin tree: `coffer admin org ...` and
// `coffer admin audit ...` (SPEC §7.1).
func (c *cli) cmdAdmin(args []string) error {
	if len(args) == 0 {
		return usagef("missing admin command: expected `coffer admin org|audit ...`")
	}
	switch args[0] {
	case "org", "orgs", "organization", "organizations":
		return c.cmdAdminOrg(args[1:])
	case "audit":
		return c.cmdAdminAudit(args[1:])
	case "help", "-h", "--help":
		c.printUsage(c.stdout)
		return nil
	default:
		return usagef("unknown admin command %q: expected `coffer admin org|audit ...`", args[0])
	}
}

// cmdAdminOrg dispatches `coffer admin org create|list|disable`.
func (c *cli) cmdAdminOrg(args []string) error {
	if len(args) == 0 {
		return usagef("missing admin org command: expected `coffer admin org create|list|disable`")
	}
	switch args[0] {
	case "create":
		return c.cmdAdminOrgCreate(args[1:])
	case "list", "ls":
		return c.cmdAdminOrgList(args[1:])
	case "disable":
		return c.cmdAdminOrgDisable(args[1:])
	default:
		return usagef("unknown admin org command %q: expected `coffer admin org create|list|disable`", args[0])
	}
}

// cmdAdminOrgCreate implements
// `coffer admin org create SLUG --owner-email EMAIL`, with the owner's initial
// password on stdin.
func (c *cli) cmdAdminOrgCreate(args []string) error {
	fs := newFlagSet("admin org create")
	var ownerEmail stringOpt
	fs.Var(&ownerEmail, "owner-email", "email address of the organization's first owner")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "admin org create SLUG --owner-email EMAIL"); err != nil {
		return err
	}
	slug := fs.Arg(0)
	if err := validateSlug("organization slug", slug); err != nil {
		return err
	}
	email, err := requiredString(fs, &ownerEmail, "--owner-email", "admin org create SLUG --owner-email EMAIL")
	if err != nil {
		return err
	}
	if err := validateEmail(email); err != nil {
		return err
	}
	password, err := c.in.password("owner password")
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	body := map[string]string{"slug": slug, "owner_email": email, "owner_password": password}
	resp, err := cl.raw(http.MethodPost, "/api/v1/admin/orgs", nil, body)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Created organization %s\n", slug)
	fmt.Fprintf(c.stdout, "Owner: %s\n", email)
	return nil
}

// cmdAdminOrgList implements `coffer admin org list`.
func (c *cli) cmdAdminOrgList(args []string) error {
	fs := newFlagSet("admin org list")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "admin org list"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/admin/orgs", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []orgRow
	if err := decodeList(resp.body, "organizations", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		status := "active"
		if r.DisabledAt.set {
			status = "disabled"
		}
		table = append(table, []string{r.Slug, r.ID, status, r.CreatedAt.String()})
	}
	return c.table([]string{"SLUG", "ID", "STATUS", "CREATED"}, table)
}

// cmdAdminOrgDisable implements `coffer admin org disable SLUG`.
func (c *cli) cmdAdminOrgDisable(args []string) error {
	fs := newFlagSet("admin org disable")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "admin org disable SLUG"); err != nil {
		return err
	}
	slug := fs.Arg(0)
	if err := validateSlug("organization slug", slug); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	path := "/api/v1/admin/orgs/" + escapePath(slug) + "/disable"
	resp, err := cl.raw(http.MethodPost, path, nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Disabled organization %s\n", slug)
	return nil
}

// cmdAdminAudit dispatches the platform audit log.
func (c *cli) cmdAdminAudit(args []string) error {
	if len(args) == 0 {
		return usagef("missing admin audit command: expected `coffer admin audit list|verify`")
	}
	switch args[0] {
	case "list", "ls":
		return c.cmdAdminAuditList(args[1:])
	case "verify":
		return c.cmdAdminAuditVerify(args[1:])
	default:
		return usagef("unknown admin audit command %q: expected `coffer admin audit list|verify`", args[0])
	}
}

// cmdAdminAuditList implements `coffer admin audit list [--limit N]`.
func (c *cli) cmdAdminAuditList(args []string) error {
	fs := newFlagSet("admin audit list")
	var limit intOpt
	fs.Var(&limit, "limit", "maximum number of events")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "admin audit list [--limit N]"); err != nil {
		return err
	}
	return c.auditList("/api/v1/admin/audit", limit, "", "", "")
}

// cmdAdminAuditVerify implements `coffer admin audit verify`.
func (c *cli) cmdAdminAuditVerify(args []string) error {
	fs := newFlagSet("admin audit verify")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "admin audit verify"); err != nil {
		return err
	}
	return c.auditVerify("/api/v1/admin/audit/verify")
}
