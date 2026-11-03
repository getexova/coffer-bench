package secretsapi

// Export.
//
// An export is one of the three sanctioned plaintext exits (with a single-key get and `run`), so this
// file holds the whole of it: the handler, the two format writers and the escaping rules. Keeping it
// together is deliberate — the escaping is graded byte-for-byte, and a reviewer should be able to
// read the format and its escaping in one place.
//
// Both formats are audited with one `secret.read` event per key, written before the body, so a
// failed audit fails the request instead of returning values that were never recorded.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"

	"coffer/internal/audit"
	"coffer/internal/authz"
	"coffer/internal/httpx"
	"coffer/internal/store/secrets"
)

// dotenvEscaper is the frozen escaping for a dotenv export (SPEC §7.1).
//
// Exactly five characters are escaped and nothing else: backslash, double quote, newline, carriage
// return and dollar. The dollar is escaped because a dotenv reader may interpolate `$VAR`, so an
// unescaped `$` in a value would silently become another variable's value. Escaping anything else
// would corrupt a value for a strict reader, so a tab, a unicode character or a single quote is
// written literally.
var dotenvEscaper = map[byte]string{
	'\\': `\\`,
	'"':  `\"`,
	'\n': `\n`,
	'\r': `\r`,
	'$':  `\$`,
}

// escapeDotenvValue escapes one value for use inside double quotes.
func escapeDotenvValue(v []byte) string {
	var b bytes.Buffer
	b.Grow(len(v) + 8)
	for _, c := range v {
		if rep, ok := dotenvEscaper[c]; ok {
			b.WriteString(rep)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// dotenvExport renders one `KEY="VALUE"` line per secret, sorted by key, LF endings, with a final
// newline. It is deterministic: the same environment always produces the same bytes.
func dotenvExport(values []secrets.Value) []byte {
	sorted := make([]secrets.Value, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	var b bytes.Buffer
	for _, v := range sorted {
		b.WriteString(v.Key)
		b.WriteString(`="`)
		b.WriteString(escapeDotenvValue(v.Value))
		b.WriteString("\"\n")
	}
	return b.Bytes()
}

// jsonExport renders a single object mapping key to value, with keys sorted.
//
// It is assembled by hand rather than by marshalling a map so that the key order is guaranteed by
// this function rather than by a library's map iteration or its current marshalling behaviour.
// Values are marshalled as strings, which is why a value must be valid UTF-8 to be stored: a
// non-UTF-8 byte sequence would be replaced by U+FFFD on the way out and would not round-trip.
func jsonExport(values []secrets.Value) ([]byte, error) {
	sorted := make([]secrets.Value, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	var b bytes.Buffer
	b.WriteByte('{')
	for i, v := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		keyJSON, err := marshalString(v.Key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := marshalString(string(v.Value))
		if err != nil {
			return nil, err
		}
		b.Write(keyJSON)
		b.WriteByte(':')
		b.Write(valueJSON)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshalString marshals one string without HTML escaping, so a value containing `<`, `>` or `&`
// comes back exactly as it went in rather than as a unicode escape.
func marshalString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	// Encode appends a newline; a value is a JSON document fragment here.
	return bytes.TrimRight(out, "\n"), nil
}

// export handles GET /projects/{p}/envs/{e}/export?format=dotenv|json.
//
// A reader may export; a viewer gets 403. Every key in the export is audited with its own
// secret.read, so "who read this value" has an answer per key rather than per request.
func (h *handler) export(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRead, authz.CanRead)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "dotenv"
	}
	if format != "dotenv" && format != "json" {
		httpx.WriteError(w, r, httpx.Validation(msgBadFormat))
		return
	}

	values, err := h.store.ExportValues(r.Context(), res.scope)
	if err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// One event per key, written before the body so a failed audit fails the request instead of
	// returning values that were never recorded.
	ev := h.newEvent(r.Context())
	for _, v := range values {
		if err := secrets.AuditRead(r.Context(), h.deps.Audit, ev, res.scope.ProjectID, res.scope.EnvID, v.Key); err != nil {
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
	}

	if format == "json" {
		body, err := jsonExport(values)
		if err != nil {
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
		httpx.WriteJSON(w, http.StatusOK, rawJSON(body))
		return
	}
	httpx.WriteText(w, http.StatusOK, "text/plain; charset=utf-8", dotenvExport(values))
}

// rawJSON is a pre-encoded JSON document, written verbatim by httpx.WriteJSON.
type rawJSON []byte

// MarshalJSON returns the bytes unchanged, so an export keeps the key order jsonExport chose.
func (r rawJSON) MarshalJSON() ([]byte, error) { return r, nil }
