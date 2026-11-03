package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// cmdAudit dispatches `coffer audit ...` (the caller's organization log).
func (c *cli) cmdAudit(args []string) error {
	if len(args) == 0 {
		return usagef("missing audit command: expected `coffer audit list|verify`")
	}
	switch args[0] {
	case "list", "ls":
		return c.cmdAuditList(args[1:])
	case "verify":
		return c.cmdAuditVerify(args[1:])
	default:
		return usagef("unknown audit command %q: expected `coffer audit list|verify`", args[0])
	}
}

// cmdAuditList implements
// `coffer audit list [--actor ID] [--action NAME] [--since RFC3339] [--limit N]`.
func (c *cli) cmdAuditList(args []string) error {
	fs := newFlagSet("audit list")
	var actor, action, since stringOpt
	var limit intOpt
	fs.Var(&actor, "actor", "filter by actor id")
	fs.Var(&action, "action", "filter by action name")
	fs.Var(&since, "since", "RFC 3339 timestamp")
	fs.Var(&limit, "limit", "maximum number of events")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "audit list [--actor ID] [--action NAME] [--since RFC3339] [--limit N]"); err != nil {
		return err
	}
	// --since is validated locally: a malformed timestamp is a usage error, not
	// a request the server has to reject.
	if since.value != "" {
		if _, err := time.Parse(time.RFC3339, since.value); err != nil {
			return usagef("invalid --since %q: use an RFC 3339 timestamp such as 2026-01-02T15:04:05Z", since.value)
		}
	}
	return c.auditList("/api/v1/audit", limit, actor.value, action.value, since.value)
}

// cmdAuditVerify implements `coffer audit verify`.
//
// A chain that fails verification is a successful HTTP call reporting
// valid:false, so it exits 9 rather than being treated as an HTTP error.
func (c *cli) cmdAuditVerify(args []string) error {
	fs := newFlagSet("audit verify")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "audit verify"); err != nil {
		return err
	}
	return c.auditVerify("/api/v1/audit/verify")
}

// auditList performs a filtered audit read and renders it.
func (c *cli) auditList(path string, limit intOpt, actor, action, since string) error {
	q := url.Values{}
	if actor != "" {
		q.Set("actor", actor)
	}
	if action != "" {
		q.Set("action", action)
	}
	if since != "" {
		q.Set("since", since)
	}
	if limit.set {
		q.Set("limit", itoa(limit.value))
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []auditRow
	if err := decodeList(resp.body, "events", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		table = append(table, []string{
			r.Seq.String(),
			r.when().String(),
			orDash(r.actor()),
			orDash(r.Action),
			orDash(r.Target),
			orDash(r.Result),
			orDash(r.SourceIP),
		})
	}
	return c.table([]string{"SEQ", "TIME", "ACTOR", "ACTION", "TARGET", "RESULT", "SOURCE IP"}, table)
}

// auditVerify reports chain validity and exits 9 when the chain is invalid.
func (c *cli) auditVerify(path string) error {
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	var result verifyResult
	if err := decodeObject(resp.body, "audit", &result); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	if c.json {
		if err := c.printJSONBytes(resp.body); err != nil {
			return err
		}
	} else if result.Valid {
		fmt.Fprintln(c.stdout, "Audit chain valid.")
	} else {
		fmt.Fprintf(c.stdout, "Audit chain INVALID at sequence %s\n", result.invalidSeq())
	}
	if !result.Valid {
		// 9 is a report, not an HTTP error: the request itself succeeded.
		return &silentError{code: exitAuditInvalid}
	}
	return nil
}
