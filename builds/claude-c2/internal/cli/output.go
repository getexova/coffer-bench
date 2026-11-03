package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitize makes server- or user-supplied text safe to print to a terminal:
// control characters (C0, DEL, C1), bidi overrides and invalid UTF-8 are
// replaced with escape sequences, so a malicious audit target or member email
// cannot inject terminal escape sequences or forge table columns.
func sanitize(s string) string {
	clean := true
	for _, r := range s {
		if needsEscape(r) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case needsEscape(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(r rune) bool {
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
		return true
	}
	switch {
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
		return true
	}
	return r == utf8.RuneError || (!unicode.IsPrint(r) && !unicode.IsSpace(r) && r != 0x200d)
}

// printRawJSON prints a JSON response body indented, preserving the server's
// key order and values.
func printRawJSON(w io.Writer, body []byte) error {
	if !json.Valid(body) {
		return genericErr("unexpected response from server")
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, bytes.TrimSpace(body), "", "  "); err != nil {
		return genericErr("unexpected response from server")
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}

// column describes one table column.
type column struct {
	header string
	get    func(map[string]any) string
}

func col(header, key string) column {
	return column{header: header, get: func(m map[string]any) string { return cell(m[key]) }}
}

// cell renders a JSON value for a table cell.
func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		if t == "" {
			return "-"
		}
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		return t.String()
	case float64:
		return fmt.Sprintf("%v", t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "?"
		}
		return string(b)
	}
}

// printTable prints rows as tab-separated columns with a header line.
func printTable(w io.Writer, cols []column, rows []map[string]any) {
	hdr := make([]string, len(cols))
	for i, c := range cols {
		hdr[i] = c.header
	}
	var b strings.Builder
	b.WriteString(strings.Join(hdr, "\t"))
	b.WriteByte('\n')
	for _, r := range rows {
		for i, c := range cols {
			if i > 0 {
				b.WriteByte('\t')
			}
			b.WriteString(sanitize(c.get(r)))
		}
		b.WriteByte('\n')
	}
	io.WriteString(w, b.String())
}

// printKV prints "key: value" lines in the given order, skipping absent keys.
func printKV(w io.Writer, m map[string]any, keys []string) {
	var b strings.Builder
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, sanitize(cell(v)))
	}
	io.WriteString(w, b.String())
}

func str(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	if n, ok := m[key].(json.Number); ok {
		return n.String()
	}
	return ""
}
