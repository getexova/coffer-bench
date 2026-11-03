package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// printJSON writes exactly one JSON document to stdout (SPEC §7.1). It ends with
// a single newline; nothing else is ever printed on a --json success path.
func (c *cli) printJSON(v any) error {
	payload, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the response as JSON: %w", err)
	}
	if _, err := c.stdout.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("cannot write to stdout: %w", err)
	}
	return nil
}

// printJSONBytes writes a JSON document that came from the server unchanged, so
// key order and formatting are the server's, and there is still exactly one
// document.
func (c *cli) printJSONBytes(body []byte) error {
	trimmed := bytes.TrimRight(body, "\r\n")
	if _, err := c.stdout.Write(trimmed); err != nil {
		return fmt.Errorf("cannot write to stdout: %w", err)
	}
	if _, err := c.stdout.Write([]byte("\n")); err != nil {
		return fmt.Errorf("cannot write to stdout: %w", err)
	}
	return nil
}

// dotenvEscaper replaces the six characters SPEC §7.1 lists and nothing else.
var dotenvEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	"\n", `\n`,
	"\r", `\r`,
	`$`, `\$`,
)

// dotenvLine renders one KEY="VALUE" line. Nothing else is escaped, so a value
// containing a tab or a single quote comes out byte for byte inside the quotes.
func dotenvLine(key, value string) string {
	return key + `="` + dotenvEscaper.Replace(value) + `"`
}

// renderDotenv renders a whole environment: sorted by key, LF line endings, and
// a final newline. An empty environment is zero bytes.
func renderDotenv(secrets map[string]string) []byte {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(dotenvLine(k, secrets[k]))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// renderJSONExport renders the json export format: a single object mapping key
// to value, with keys sorted.
func renderJSONExport(secrets map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		valueJSON, err := json.Marshal(secrets[k])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// writeRaw writes bytes to stdout with nothing added.
func (c *cli) writeRaw(data []byte) error {
	if _, err := c.stdout.Write(data); err != nil {
		return fmt.Errorf("cannot write to stdout: %w", err)
	}
	return nil
}

// writeValue writes a secret value. On a terminal a newline is appended so the
// shell prompt does not run into the value; through a pipe the exact bytes are
// written and nothing else (SPEC §7.1).
func (c *cli) writeValue(value []byte) error {
	if err := c.writeRaw(value); err != nil {
		return err
	}
	if c.stdoutTTY() {
		if _, err := c.stdout.Write([]byte("\n")); err != nil {
			return fmt.Errorf("cannot write to stdout: %w", err)
		}
	}
	return nil
}

// table prints aligned rows. A nil writer target means stdout.
func (c *cli) table(header []string, rows [][]string) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	writeRow(tw, header)
	sep := make([]string, len(header))
	for i := range sep {
		sep[i] = strings.Repeat("-", len(header[i]))
	}
	writeRow(tw, sep)
	for _, row := range rows {
		writeRow(tw, row)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("cannot format the table: %w", err)
	}
	return c.writeRaw(buf.Bytes())
}

func writeRow(w io.Writer, cells []string) {
	for i, cell := range cells {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, sanitizeCell(cell))
	}
	fmt.Fprintln(w)
}

// sanitizeCell keeps a server-provided string from breaking the table layout.
func sanitizeCell(s string) string {
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "-"
	}
	return s
}

// orDash renders an empty field as "-" so a table stays readable.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// formatTime renders an RFC 3339 timestamp for a table cell.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatTimePtr renders an optional timestamp.
func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return formatTime(*t)
}

// printMessage writes a human-readable success line, unless --json is active.
func (c *cli) printMessage(format string, args ...any) error {
	if c.json {
		return nil
	}
	fmt.Fprintf(c.stdout, format, args...)
	return nil
}

// jsonOr prints the server's document under --json (exactly one document), and
// otherwise calls human to render a readable line.
func (c *cli) jsonOr(doc any, human func()) error {
	if c.json {
		if doc == nil {
			return c.printJSON(map[string]any{"status": "ok"})
		}
		return c.printJSON(doc)
	}
	if human != nil {
		human()
	}
	return nil
}
