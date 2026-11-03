package secretsapi

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"coffer/internal/store/secrets"
)

// TestEscapeDotenvValue pins the frozen escaping exactly (SPEC §7.1): inside the quotes, escape
// backslash as \\, double quote as \", newline as \n, carriage return as \r and dollar as \$, and
// escape nothing else.
func TestEscapeDotenvValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{`back\slash`, `back\\slash`},
		{`double"quote`, `double\"quote`},
		{"new\nline", `new\nline`},
		{"carriage\rreturn", `carriage\rreturn`},
		{"dollar$sign", `dollar\$sign`},
		{"${VAR}", `\${VAR}`},
		// Nothing else is escaped: a tab, a single quote, a backtick, a colon, an equals sign,
		// unicode and a hash are all written literally.
		{"tab\there", "tab\there"},
		{"single'quote", "single'quote"},
		{"back`tick", "back`tick"},
		{"a=b:c", "a=b:c"},
		{"hash#mark", "hash#mark"},
		{"héllo→", "héllo→"},
		{"!bang*star?q", "!bang*star?q"},
		// The full set in one value, in a single pass.
		{"a\\b\"c\nd\re$f", `a\\b\"c\nd\re\$f`},
	}
	for _, tc := range cases {
		if got := escapeDotenvValue([]byte(tc.in)); got != tc.want {
			t.Errorf("escapeDotenvValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEscapeDotenvIsSinglePass checks a backslash is not escaped twice: the escape of `\n` must be
// backslash followed by 'n', not a doubly escaped backslash.
func TestEscapeDotenvIsSinglePass(t *testing.T) {
	got := escapeDotenvValue([]byte(`\n`))
	if got != `\\n` {
		t.Fatalf("got %q, want %q", got, `\\n`)
	}
}

// TestDotenvExport covers the document rules: one line per key, sorted by key, LF endings, a final
// newline, and only live values.
func TestDotenvExport(t *testing.T) {
	values := []secrets.Value{
		{Key: "ZED", Value: []byte("last")},
		{Key: "ALPHA", Value: []byte("first")},
		{Key: "EMPTY", Value: []byte("")},
		{Key: "MULTI", Value: []byte("a\nb")},
	}
	got := string(dotenvExport(values))

	want := "ALPHA=\"first\"\n" +
		"EMPTY=\"\"\n" +
		"MULTI=\"a\\nb\"\n" +
		"ZED=\"last\"\n"
	if got != want {
		t.Fatalf("dotenv export mismatch\n got: %q\nwant: %q", got, want)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatal("dotenv export has no final newline")
	}
	if strings.Contains(got, "\r") {
		t.Fatal("dotenv export contains a carriage return outside an escaped value")
	}
}

// TestDotenvExportEmptyEnvironment checks an empty environment exports nothing at all: no lines and
// no final newline, rather than a single blank line.
func TestDotenvExportEmptyEnvironment(t *testing.T) {
	if got := dotenvExport(nil); len(got) != 0 {
		t.Fatalf("empty export produced %q", got)
	}
}

// TestDotenvExportIsDeterministic checks the same input always produces the same bytes, in the
// order the sort chose rather than in map or query order.
func TestDotenvExportIsDeterministic(t *testing.T) {
	values := []secrets.Value{
		{Key: "B", Value: []byte("2")},
		{Key: "A", Value: []byte("1")},
		{Key: "C", Value: []byte("3")},
	}
	first := dotenvExport(values)
	for i := 0; i < 20; i++ {
		if !bytes.Equal(dotenvExport(values), first) {
			t.Fatal("dotenv export is not deterministic")
		}
	}
	// And the input slice is not reordered as a side effect.
	if values[0].Key != "B" {
		t.Fatal("dotenvExport mutated its input")
	}
}

// TestJSONExport covers the object shape, sorted keys and exact values.
func TestJSONExport(t *testing.T) {
	values := []secrets.Value{
		{Key: "ZED", Value: []byte("last")},
		{Key: "ALPHA", Value: []byte("first")},
		{Key: "EMPTY", Value: []byte("")},
		{Key: "HTML", Value: []byte("<a>&b")},
		{Key: "UNI", Value: []byte("héllo→")},
		{Key: "QUOTE", Value: []byte(`a"b\c`)},
		{Key: "NEWLINE", Value: []byte("a\nb")},
	}
	body, err := jsonExport(values)
	if err != nil {
		t.Fatalf("jsonExport: %v", err)
	}
	want := `{"ALPHA":"first","EMPTY":"","HTML":"<a>&b","NEWLINE":"a\nb","QUOTE":"a\"b\\c","UNI":"héllo→","ZED":"last"}`
	if string(body) != want {
		t.Fatalf("json export mismatch\n got: %s\nwant: %s", body, want)
	}

	// It must be valid JSON that decodes back to the exact values.
	var round map[string]string
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	for _, v := range values {
		if round[v.Key] != string(v.Value) {
			t.Errorf("key %s round-tripped to %q, want %q", v.Key, round[v.Key], v.Value)
		}
	}
}

// TestJSONExportDoesNotEscapeHTML checks a value with angle brackets is not turned into unicode
// escapes, which would not be byte-exact.
func TestJSONExportDoesNotEscapeHTML(t *testing.T) {
	body, err := jsonExport([]secrets.Value{{Key: "K", Value: []byte("<&>")}})
	if err != nil {
		t.Fatalf("jsonExport: %v", err)
	}
	if strings.Contains(string(body), `\u003c`) {
		t.Fatalf("HTML escaping was applied: %s", body)
	}
}

// TestJSONExportEmptyEnvironment checks an empty environment is an empty object.
func TestJSONExportEmptyEnvironment(t *testing.T) {
	body, err := jsonExport(nil)
	if err != nil {
		t.Fatalf("jsonExport: %v", err)
	}
	if string(body) != "{}" {
		t.Fatalf("empty export produced %q, want {}", body)
	}
}

// TestRawJSONPassesThrough checks the pre-encoded export is written verbatim, keeping the key order
// jsonExport chose instead of re-sorting through a map.
func TestRawJSONPassesThrough(t *testing.T) {
	original := []byte(`{"B":"2","A":"1"}`)
	out, err := json.Marshal(rawJSON(original))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("rawJSON was re-encoded: %s", out)
	}
}

// TestValidateValue covers the value bounds and the UTF-8 requirement.
func TestValidateValue(t *testing.T) {
	if err := validateValue(nil); err != nil {
		t.Fatalf("an empty value must be valid: %v", err)
	}
	if err := validateValue([]byte("")); err != nil {
		t.Fatalf("an empty value must be valid: %v", err)
	}
	if err := validateValue(bytes.Repeat([]byte("a"), 65536)); err != nil {
		t.Fatalf("a 65536-byte value must be valid: %v", err)
	}
	if err := validateValue(bytes.Repeat([]byte("a"), 65537)); err != secrets.ErrValueTooLarge {
		t.Fatalf("a 65537-byte value: got %v, want ErrValueTooLarge", err)
	}
	if err := validateValue([]byte{0xff, 0xfe}); err != secrets.ErrInvalidUTF8 {
		t.Fatalf("invalid UTF-8: got %v, want ErrInvalidUTF8", err)
	}
	// A multi-byte character counts in bytes, not runes.
	if err := validateValue(bytes.Repeat([]byte("é"), 32768)); err != nil {
		t.Fatalf("65536 bytes of multi-byte characters must be valid: %v", err)
	}
	if err := validateValue(bytes.Repeat([]byte("é"), 32769)); err != secrets.ErrValueTooLarge {
		t.Fatalf("65538 bytes of multi-byte characters: got %v, want ErrValueTooLarge", err)
	}
}

// TestValidKeyReachable checks the key format the handlers enforce is the frozen one.
func TestValidKeyReachable(t *testing.T) {
	valid := []string{"A", "_", "A_B", "A1", "_LEADING_UNDERSCORE", strings.Repeat("A", 128)}
	for _, k := range valid {
		if !secrets.ValidKey(k) {
			t.Errorf("%q should be a valid key", k)
		}
	}
	invalid := []string{
		"", "lower", "Mixed", "1LEADING_DIGIT", "WITH-DASH", "WITH SPACE", "WITH.DOT",
		strings.Repeat("A", 129), "A\n", "A\x00",
	}
	for _, k := range invalid {
		if secrets.ValidKey(k) {
			t.Errorf("%q should not be a valid key", k)
		}
	}
}

// TestParseVersion covers the version path segment: decimal, starting at 1.
func TestParseVersion(t *testing.T) {
	if v, ok := parseVersion("1"); !ok || v != 1 {
		t.Fatalf("parseVersion(1) = %d, %v", v, ok)
	}
	if v, ok := parseVersion("9223372036854775807"); !ok || v != 9223372036854775807 {
		t.Fatalf("the largest int64 version should parse: %d, %v", v, ok)
	}
	for _, in := range []string{"", "0", "-1", "1.0", "abc", " 1", "1 ", "+1", "0x10", "999999999999999999999999", "9223372036854775808"} {
		if _, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) should fail", in)
		}
	}
}

// TestPendingResponseShape pins the 202 body required by the frozen interface: it is not an error
// envelope, and it names the change.
func TestPendingResponseShape(t *testing.T) {
	body, err := json.Marshal(pendingResponse{Status: "pending", ChangeID: "chg_abc"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(body) != `{"status":"pending","change_id":"chg_abc"}` {
		t.Fatalf("unexpected 202 body: %s", body)
	}
}

// TestErrorMessagesCarryNoDetail checks the generic messages really are generic: no SQL, no path,
// no value placeholder.
func TestErrorMessagesCarryNoDetail(t *testing.T) {
	for name, msg := range map[string]string{
		"not found":   msgNotFound,
		"forbidden":   msgForbidden,
		"conflict":    msgConflict,
		"stale":       msgStale,
		"resolved":    msgResolved,
		"bad key":     msgBadKey,
		"bad value":   msgBadValue,
		"bad version": msgBadVersion,
		"bad format":  msgBadFormat,
		"bad status":  msgBadStatus,
	} {
		lower := strings.ToLower(msg)
		for _, leak := range []string{"select", "insert", "update", "from ", "secrets.", "internal", "/", "%s", "%v"} {
			if strings.Contains(lower, leak) {
				t.Errorf("%s message %q leaks %q", name, msg, leak)
			}
		}
	}
}
