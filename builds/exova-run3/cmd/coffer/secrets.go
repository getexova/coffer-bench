package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// cmdSecrets dispatches `coffer secrets ...` (SPEC §7.1).
func (c *cli) cmdSecrets(args []string) error {
	if len(args) == 0 {
		return usagef("missing secrets command: expected `coffer secrets list|get|set|delete|history|rollback|export`")
	}
	switch args[0] {
	case "list", "ls":
		return c.cmdSecretsList(args[1:])
	case "get":
		return c.cmdSecretsGet(args[1:])
	case "set":
		return c.cmdSecretsSet(args[1:])
	case "delete", "rm":
		return c.cmdSecretsDelete(args[1:])
	case "history", "versions":
		return c.cmdSecretsHistory(args[1:])
	case "rollback":
		return c.cmdSecretsRollback(args[1:])
	case "export":
		return c.cmdSecretsExport(args[1:])
	default:
		return usagef("unknown secrets command %q: expected `coffer secrets list|get|set|delete|history|rollback|export`", args[0])
	}
}

// cmdSecretsList implements `coffer secrets list -p P -e E`: metadata only.
func (c *cli) cmdSecretsList(args []string) error {
	const synopsis = "secrets list -p P -e E"
	fs := newFlagSet("secrets list")
	var scope secretScope
	scope.register(fs)
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
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, envPath(project, env)+"/secrets", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []secretRow
	if err := decodeList(resp.body, "secrets", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		table = append(table, []string{r.Key, r.Version.String(), r.UpdatedAt.String(), orDash(r.UpdatedBy)})
	}
	return c.table([]string{"KEY", "VERSION", "UPDATED", "UPDATED BY"}, table)
}

// cmdSecretsGet implements `coffer secrets get KEY -p P -e E [--version N]`.
//
// Without --json the value's bytes are written to stdout exactly: no newline is
// added when stdout is a pipe, so `coffer secrets get KEY ... > file` reproduces
// the stored value byte for byte (SPEC §7.1).
func (c *cli) cmdSecretsGet(args []string) error {
	const synopsis = "secrets get KEY -p P -e E [--version N]"
	fs := newFlagSet("secrets get")
	var scope secretScope
	var version intOpt
	scope.register(fs)
	fs.Var(&version, "version", "read a specific version")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, synopsis); err != nil {
		return err
	}
	key := fs.Arg(0)
	if err := validateSecretKey(key); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}

	path := secretPath(project, env, key)
	if version.set {
		if version.value < 1 {
			return usagef("invalid --version %d: versions start at 1", version.value)
		}
		path += "/versions/" + itoa(version.value)
	}
	resp, err := cl.raw(http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}

	if c.json {
		return c.printJSONBytes(resp.body)
	}
	value, err := extractValue(resp.body)
	if err != nil {
		return err
	}
	return c.writeValue(value)
}

// cmdSecretsSet implements
// `coffer secrets set KEY [VALUE] -p P -e E [--expect-version N]`.
//
// With no VALUE the bytes on stdin are the value, read to EOF and stored
// exactly: no newline trimming, so a piped file round-trips byte for byte.
func (c *cli) cmdSecretsSet(args []string) error {
	const synopsis = "secrets set KEY [VALUE] -p P -e E [--expect-version N]"
	fs := newFlagSet("secrets set")
	var scope secretScope
	var expect intOpt
	scope.register(fs)
	fs.Var(&expect, "expect-version", "only write if the current version matches")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return usagef("missing argument: expected `coffer %s`", synopsis)
	}
	if fs.NArg() > 2 {
		return usagef("unexpected argument %q: expected `coffer %s`", fs.Arg(2), synopsis)
	}
	key := fs.Arg(0)
	if err := validateSecretKey(key); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}

	var value []byte
	if fs.NArg() == 2 {
		value = []byte(fs.Arg(1))
	} else {
		value, err = c.in.rest()
		if err != nil {
			return err
		}
	}

	cl, err := c.authClient()
	if err != nil {
		return err
	}
	body := map[string]any{"value": string(value)}
	if expect.set {
		body["expected_version"] = expect.value
	}
	resp, err := cl.raw(http.MethodPut, secretPath(project, env, key), nil, body)
	if err != nil {
		return err
	}
	return c.reportWrite(resp, key, "Set")
}

// cmdSecretsDelete implements `coffer secrets delete KEY -p P -e E`.
func (c *cli) cmdSecretsDelete(args []string) error {
	const synopsis = "secrets delete KEY -p P -e E"
	fs := newFlagSet("secrets delete")
	var scope secretScope
	scope.register(fs)
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, synopsis); err != nil {
		return err
	}
	key := fs.Arg(0)
	if err := validateSecretKey(key); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodDelete, secretPath(project, env, key), nil, nil)
	if err != nil {
		return err
	}
	return c.reportWrite(resp, key, "Deleted")
}

// cmdSecretsHistory implements `coffer secrets history KEY -p P -e E`.
func (c *cli) cmdSecretsHistory(args []string) error {
	const synopsis = "secrets history KEY -p P -e E"
	fs := newFlagSet("secrets history")
	var scope secretScope
	scope.register(fs)
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, synopsis); err != nil {
		return err
	}
	key := fs.Arg(0)
	if err := validateSecretKey(key); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, secretPath(project, env, key)+"/versions", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []versionRow
	if err := decodeList(resp.body, "versions", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		deleted := "no"
		if r.Deleted {
			deleted = "yes"
		}
		table = append(table, []string{r.Version.String(), deleted, r.CreatedAt.String(), orDash(r.CreatedBy)})
	}
	return c.table([]string{"VERSION", "DELETED", "CREATED", "CREATED BY"}, table)
}

// cmdSecretsRollback implements `coffer secrets rollback KEY --to N -p P -e E`.
func (c *cli) cmdSecretsRollback(args []string) error {
	const synopsis = "secrets rollback KEY --to N -p P -e E"
	fs := newFlagSet("secrets rollback")
	var scope secretScope
	var to intOpt
	scope.register(fs)
	fs.Var(&to, "to", "version to roll back to")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, synopsis); err != nil {
		return err
	}
	key := fs.Arg(0)
	if err := validateSecretKey(key); err != nil {
		return err
	}
	if !to.set {
		return usagef("missing required flag --to: expected `coffer %s`", synopsis)
	}
	if to.value < 1 {
		return usagef("invalid --to %d: versions start at 1", to.value)
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	body := map[string]any{"to": to.value}
	resp, err := cl.raw(http.MethodPost, secretPath(project, env, key)+"/rollback", nil, body)
	if err != nil {
		return err
	}
	return c.reportWrite(resp, key, "Rolled back")
}

// cmdSecretsExport implements
// `coffer secrets export -p P -e E --format dotenv|json`.
//
// The server's bytes are passed through unchanged for both formats rather than
// re-escaping: the server owns the escaping, a re-render could only introduce a
// difference, and pass-through is what makes `coffer secrets export --format
// dotenv > .env` byte-identical to what the API produced.
func (c *cli) cmdSecretsExport(args []string) error {
	const synopsis = "secrets export -p P -e E --format dotenv|json"
	fs := newFlagSet("secrets export")
	var scope secretScope
	var format stringOpt
	scope.register(fs)
	fs.Var(&format, "format", "dotenv or json")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, synopsis); err != nil {
		return err
	}
	if _, err := requiredString(fs, &format, "--format", synopsis); err != nil {
		return err
	}
	if err := validateFormat(format.value); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("format", format.value)
	resp, err := cl.raw(http.MethodGet, envPath(project, env)+"/export", q, nil)
	if err != nil {
		return err
	}
	// dotenv is passed through byte for byte: the server owns the escaping and a
	// re-render could only introduce a difference, which is what makes
	// `coffer secrets export --format dotenv > .env` exact.
	//
	// json is a single document rather than a file of exact bytes, so it gets one
	// trailing newline if the server did not send one: without it the shell prompt
	// runs into the closing brace.
	if format.value == "json" && !bytes.HasSuffix(resp.body, []byte("\n")) {
		return c.writeRaw(append(resp.body, '\n'))
	}
	return c.writeRaw(resp.body)
}

// reportWrite renders the outcome of a write: 200 is applied, 202 is pending
// approval. A pending write prints the change ID and exits 7 (SPEC §7.1).
func (c *cli) reportWrite(resp *response, key, verb string) error {
	var result writeResult
	if len(bytes.TrimSpace(resp.body)) > 0 {
		_ = json.Unmarshal(resp.body, &result)
	}
	if resp.status == http.StatusAccepted {
		changeID := firstNonEmpty(result.ChangeID, changeIDFromBody(resp.body))
		if changeID == "" {
			return &apiError{
				Status:  resp.status,
				Code:    "pending",
				Message: "the write is pending approval but the server returned no change id",
			}
		}
		if c.json {
			if err := c.printJSON(map[string]any{"status": "pending", "change_id": changeID}); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(c.stdout, changeID)
		}
		return &silentError{code: exitPending}
	}
	if c.json {
		if len(bytes.TrimSpace(resp.body)) == 0 {
			return c.printJSON(map[string]any{"status": "ok", "key": key})
		}
		return c.printJSONBytes(resp.body)
	}
	if result.Version.set {
		fmt.Fprintf(c.stdout, "%s %s (version %s)\n", verb, key, result.Version.String())
	} else {
		fmt.Fprintf(c.stdout, "%s %s\n", verb, key)
	}
	return nil
}

// changeIDFromBody finds a change id in a body whose shape is not the documented
// one, so a server variation does not turn a pending write into exit 1.
func changeIDFromBody(body []byte) string {
	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		return ""
	}
	for _, field := range []string{"change_id", "change", "id"} {
		if v, ok := generic[field].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// extractValue pulls the value out of a single-key read. The response is
// {"key","version","value"}; a body that is already the raw value is also
// accepted, so the CLI never mangles what the server sent.
func extractValue(body []byte) ([]byte, error) {
	var doc struct {
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(body, &doc); err == nil && doc.Value != nil {
		return []byte(*doc.Value), nil
	}
	if len(body) > 0 && (body[0] == '{' || body[0] == '[') {
		return nil, fmt.Errorf("the server returned a response without a value")
	}
	return body, nil
}

// itoa renders an int64 without pulling strconv into this file's import list
// twice; it is only used for path segments.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
