package main

import (
	"fmt"
	"net/http"
)

// cmdChange dispatches `coffer change ...` (SPEC §7.1).
func (c *cli) cmdChange(args []string) error {
	if len(args) == 0 {
		return usagef("missing change command: expected `coffer change list|approve|reject`")
	}
	switch args[0] {
	case "list", "ls":
		return c.cmdChangeList(args[1:])
	case "approve":
		return c.cmdChangeResolve(args[1:], "approve")
	case "reject":
		return c.cmdChangeResolve(args[1:], "reject")
	default:
		return usagef("unknown change command %q: expected `coffer change list|approve|reject`", args[0])
	}
}

// cmdChangeList implements
// `coffer change list [--status pending|approved|rejected|stale]`.
func (c *cli) cmdChangeList(args []string) error {
	fs := newFlagSet("change list")
	var status stringOpt
	fs.Var(&status, "status", "pending, approved, rejected or stale")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "change list [--status pending|approved|rejected|stale]"); err != nil {
		return err
	}
	if status.set && status.value != "" {
		if err := validateChangeStatus(status.value); err != nil {
			return err
		}
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/changes", values("status", status.value), nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []changeRow
	if err := decodeList(resp.body, "changes", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		target := r.Key
		if r.Project != "" || r.Env != "" {
			target = r.Project + "/" + r.Env + ":" + r.Key
		}
		table = append(table, []string{
			r.ID,
			r.Status,
			r.Op,
			target,
			orDash(firstNonEmpty(r.Proposer, r.ProposerID)),
			r.CreatedAt.String(),
		})
	}
	return c.table([]string{"ID", "STATUS", "OP", "TARGET", "PROPOSER", "CREATED"}, table)
}

// cmdChangeResolve implements `coffer change approve ID` and
// `coffer change reject ID`.
func (c *cli) cmdChangeResolve(args []string, action string) error {
	fs := newFlagSet("change " + action)
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "change "+action+" ID"); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return usagef("missing change ID: expected `coffer change %s ID`", action)
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	path := "/api/v1/changes/" + escapePath(id) + "/" + action
	resp, err := cl.raw(http.MethodPost, path, nil, nil)
	if err != nil {
		return err
	}
	// Past tense of the two actions, spelled out rather than built by appending
	// "d": "reject" + "d" is "rejectd".
	pastTense := "approved"
	if action == "reject" {
		pastTense = "rejected"
	}
	if c.json {
		if len(resp.body) == 0 {
			return c.printJSON(map[string]any{"status": pastTense, "change_id": id})
		}
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "%s change %s\n", capitalize(pastTense), id)
	return nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}
