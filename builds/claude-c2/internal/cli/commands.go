package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ctx is the per-command execution context.
type ctx struct {
	app  *App
	cmd  *command
	args []string
	f    map[string]string
}

func (c *ctx) flag(name string) string { return c.f[name] }

func (c *ctx) has(name string) bool { _, ok := c.f[name]; return ok }

func (c *ctx) json() bool { return c.f["json"] == "true" }

func (c *ctx) out() io.Writer { return c.app.Stdout }

// intFlag parses an optional integer flag. A malformed value is a validation
// error (exit 6), matching what the server would answer.
func (c *ctx) intFlag(name string) (int64, bool, error) {
	v, ok := c.f[name]
	if !ok {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false, validationErr("--%s must be an integer, got %q", name, v)
	}
	return n, true, nil
}

var commands []*command

func init() {
	commands = []*command{
		{path: []string{"login"}, usage: "--email EMAIL [--url URL]   (password on stdin)", help: "log in and store a personal access token", flags: []string{"email"}, required: []string{"email"}, run: cmdLogin},
		{path: []string{"logout"}, help: "revoke the current token and forget it", run: cmdLogout},
		{path: []string{"whoami"}, help: "show the current identity", run: cmdWhoami},
		{path: []string{"passwd"}, usage: "  (stdin: current password line, then new password line)", help: "change your password", run: cmdPasswd},

		{path: []string{"admin", "org", "create"}, usage: "SLUG --owner-email EMAIL   (owner password on stdin)", help: "create an organization and its first owner", flags: []string{"owner-email"}, required: []string{"owner-email"}, minArgs: 1, maxArgs: 1, run: cmdAdminOrgCreate},
		{path: []string{"admin", "org", "list"}, help: "list organizations", run: cmdAdminOrgList},
		{path: []string{"admin", "org", "disable"}, usage: "SLUG", help: "disable an organization", minArgs: 1, maxArgs: 1, run: cmdAdminOrgDisable},
		{path: []string{"admin", "audit", "list"}, usage: "[--limit N]", help: "list the platform audit log", flags: []string{"limit"}, run: cmdAdminAuditList},
		{path: []string{"admin", "audit", "verify"}, help: "verify the platform audit chain", run: cmdAdminAuditVerify},

		{path: []string{"member", "add"}, usage: "EMAIL --role member|admin|owner   (initial password on stdin)", help: "add a member", flags: []string{"role"}, required: []string{"role"}, minArgs: 1, maxArgs: 1, run: cmdMemberAdd},
		{path: []string{"member", "list"}, help: "list members", run: cmdMemberList},
		{path: []string{"member", "role"}, usage: "EMAIL member|admin|owner", help: "change a member's role", minArgs: 2, maxArgs: 2, run: cmdMemberRole},
		{path: []string{"member", "remove"}, usage: "EMAIL", help: "remove a member", minArgs: 1, maxArgs: 1, run: cmdMemberRemove},
		{path: []string{"grant", "set"}, usage: "EMAIL -p PROJECT --level viewer|reader|writer", help: "grant a member access to a project", flags: []string{"project", "level"}, required: []string{"project", "level"}, minArgs: 1, maxArgs: 1, run: cmdGrantSet},
		{path: []string{"grant", "revoke"}, usage: "EMAIL -p PROJECT", help: "revoke a member's project grant", flags: []string{"project"}, required: []string{"project"}, minArgs: 1, maxArgs: 1, run: cmdGrantRevoke},

		{path: []string{"project", "create"}, usage: "SLUG", help: "create a project", minArgs: 1, maxArgs: 1, run: cmdProjectCreate},
		{path: []string{"project", "list"}, help: "list visible projects", run: cmdProjectList},
		{path: []string{"env", "create"}, usage: "SLUG -p PROJECT [--protected]", help: "create an environment", flags: []string{"project", "protected"}, required: []string{"project"}, minArgs: 1, maxArgs: 1, run: cmdEnvCreate},
		{path: []string{"env", "list"}, usage: "-p PROJECT", help: "list environments", flags: []string{"project"}, required: []string{"project"}, run: cmdEnvList},

		{path: []string{"secrets", "list"}, usage: "-p P -e E", help: "list secret names and metadata", flags: pe(), required: pe(), run: cmdSecretsList},
		{path: []string{"secrets", "get"}, usage: "KEY -p P -e E [--version N]", help: "print a secret value", flags: pe("version"), required: pe(), minArgs: 1, maxArgs: 1, run: cmdSecretsGet},
		{path: []string{"secrets", "set"}, usage: "KEY [VALUE] -p P -e E [--expect-version N]   (no VALUE: read stdin to EOF)", help: "set a secret", flags: pe("expect-version"), required: pe(), minArgs: 1, maxArgs: 2, run: cmdSecretsSet},
		{path: []string{"secrets", "delete"}, usage: "KEY -p P -e E [--expect-version N]", help: "delete a secret (tombstone)", flags: pe("expect-version"), required: pe(), minArgs: 1, maxArgs: 1, run: cmdSecretsDelete},
		{path: []string{"secrets", "history"}, usage: "KEY -p P -e E", help: "list a secret's versions", flags: pe(), required: pe(), minArgs: 1, maxArgs: 1, run: cmdSecretsHistory},
		{path: []string{"secrets", "rollback"}, usage: "KEY --to N -p P -e E [--expect-version N]", help: "restore an earlier version as a new version", flags: pe("to", "expect-version"), required: pe("to"), minArgs: 1, maxArgs: 1, run: cmdSecretsRollback},
		{path: []string{"secrets", "export"}, usage: "-p P -e E --format dotenv|json", help: "export all secrets", flags: pe("format"), required: pe(), run: cmdSecretsExport},
		{path: []string{"run"}, usage: "-p P -e E -- COMMAND [ARGS...]", help: "run a command with secrets in its environment", flags: pe(), required: pe(), minArgs: 1, maxArgs: -1, stopAt: true, run: cmdRun},

		{path: []string{"change", "list"}, usage: "[--status pending|approved|rejected|stale]", help: "list change requests", flags: []string{"status"}, run: cmdChangeList},
		{path: []string{"change", "approve"}, usage: "ID", help: "approve a change request", minArgs: 1, maxArgs: 1, run: cmdChangeApprove},
		{path: []string{"change", "reject"}, usage: "ID", help: "reject a change request", minArgs: 1, maxArgs: 1, run: cmdChangeReject},

		{path: []string{"token", "create"}, usage: "-p P -e E --access read|read-write --ttl DURATION [--name NAME]", help: "issue a service token (printed once)", flags: pe("access", "ttl", "name"), required: pe("access", "ttl"), run: cmdTokenCreate},
		{path: []string{"token", "list"}, help: "list service tokens", run: cmdTokenList},
		{path: []string{"token", "revoke"}, usage: "ID", help: "revoke a service token", minArgs: 1, maxArgs: 1, run: cmdTokenRevoke},

		{path: []string{"audit", "list"}, usage: "[--actor ID] [--action NAME] [--since RFC3339] [--limit N]", help: "list the organization audit log", flags: []string{"actor", "action", "since", "limit"}, run: cmdAuditList},
		{path: []string{"audit", "verify"}, help: "verify the organization audit chain", run: cmdAuditVerify},

		{path: []string{"help"}, help: "show help", maxArgs: -1, run: cmdHelp},
		{path: []string{"version"}, help: "print the CLI version", run: cmdVersion},
	}
}

func pe(extra ...string) []string { return append([]string{"project", "env"}, extra...) }

func (a *App) run(args []string) error {
	if len(args) == 0 {
		return usageErr("coffer COMMAND [ARGS] (see `coffer help`)", "missing command")
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		a.printHelp(a.Stdout)
		return nil
	}
	cmd, rest, err := resolve(args)
	if err != nil {
		if hasHelp(args) {
			a.printHelp(a.Stdout)
			return nil
		}
		return usageErr("coffer COMMAND [ARGS] (see `coffer help`)", "%s", err.Error())
	}
	p, err := parseFlags(cmd, rest)
	if err != nil {
		return err
	}
	if v, ok := p.flags["json"]; ok {
		a.jsonOut = v == "true"
	}
	if p.flags["help"] == "true" {
		fmt.Fprintf(a.Stdout, "usage: %s\n  %s\n", cmd.usageLine(), cmd.help)
		return nil
	}
	return cmd.run(&ctx{app: a, cmd: cmd, args: p.args, f: p.flags})
}

func hasHelp(args []string) bool {
	for _, s := range args {
		if s == "--" {
			return false
		}
		if s == "--help" || s == "-h" {
			return true
		}
	}
	return false
}

func (a *App) printHelp(w io.Writer) {
	var b strings.Builder
	b.WriteString("coffer - client for the Coffer secrets service\n\nusage: coffer [--url URL] [--json] COMMAND [ARGS]\n\ncommands:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-26s %s\n", c.name(), c.help)
	}
	b.WriteString("\nenvironment: COFFER_URL (server), COFFER_TOKEN (token; disables the config file)\n")
	io.WriteString(w, b.String())
}

func cmdHelp(c *ctx) error {
	if len(c.args) > 0 {
		if cmd := findCommand(c.args); cmd != nil {
			fmt.Fprintf(c.out(), "usage: %s\n  %s\n", cmd.usageLine(), cmd.help)
			return nil
		}
	}
	c.app.printHelp(c.out())
	return nil
}

func cmdVersion(c *ctx) error {
	if c.json() {
		return writeJSON(c.out(), map[string]string{"version": Version})
	}
	fmt.Fprintf(c.out(), "coffer %s\n", Version)
	return nil
}
