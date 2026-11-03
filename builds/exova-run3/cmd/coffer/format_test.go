package main

import (
	"strings"
	"testing"
)

// TestDotenvEscaping pins the SPEC §7.1 escaping table: only backslash, double
// quote, newline, carriage return and dollar are escaped, and nothing else.
func TestDotenvEscaping(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"plain", "value", `KEY="value"`},
		{"empty", "", `KEY=""`},
		{"backslash", `a\b`, `KEY="a\\b"`},
		{"double quote", `a"b`, `KEY="a\"b"`},
		{"newline", "a\nb", `KEY="a\nb"`},
		{"carriage return", "a\rb", `KEY="a\rb"`},
		{"dollar", "a$b", `KEY="a\$b"`},
		{"all five at once", "\\\"\n\r$", `KEY="\\\"\n\r\$"`},
		{"tab is not escaped", "a\tb", "KEY=\"a\tb\""},
		{"single quote is not escaped", "a'b", `KEY="a'b"`},
		{"backtick is not escaped", "a`b", "KEY=\"a`b\""},
		{"equals is not escaped", "a=b", `KEY="a=b"`},
		{"hash is not escaped", "a#b", `KEY="a#b"`},
		{"utf8 is not escaped", "héllo ✓", `KEY="héllo ✓"`},
		{"interpolation attempt is neutralised", "${HOME}", `KEY="\${HOME}"`},
		{"dollar without braces", "$HOME", `KEY="\$HOME"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dotenvLine("KEY", tc.value); got != tc.want {
				t.Fatalf("dotenvLine(KEY, %q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestRenderDotenv covers the whole-file rules: sorted by key, LF endings and a
// final newline.
func TestRenderDotenv(t *testing.T) {
	secrets := map[string]string{
		"ZULU":  "last",
		"ALPHA": "first",
		"MIKE":  "middle",
	}
	want := "ALPHA=\"first\"\nMIKE=\"middle\"\nZULU=\"last\"\n"
	if got := string(renderDotenv(secrets)); got != want {
		t.Fatalf("renderDotenv = %q, want %q", got, want)
	}
}

// TestRenderDotenvEmptyIsZeroBytes: an empty environment exports nothing at all,
// not a stray newline.
func TestRenderDotenvEmptyIsZeroBytes(t *testing.T) {
	if got := renderDotenv(nil); len(got) != 0 {
		t.Fatalf("renderDotenv(nil) = %q, want empty", got)
	}
}

// TestRenderDotenvRoundTripsThroughAnEnvParser proves the escaping is lossless
// for the characters that matter: a consumer that unescapes the five sequences
// recovers the original bytes.
func TestRenderDotenvRoundTripsThroughAnEnvParser(t *testing.T) {
	original := "a\\b\"c\nd\re$f"
	line := dotenvLine("KEY", original)
	if !strings.HasPrefix(line, `KEY="`) || !strings.HasSuffix(line, `"`) {
		t.Fatalf("line = %q, want KEY=\"...\"", line)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(line, `KEY="`), `"`)
	unescaped := strings.NewReplacer(
		`\\`, `\`,
		`\"`, `"`,
		`\n`, "\n",
		`\r`, "\r",
		`\$`, `$`,
	).Replace(body)
	if unescaped != original {
		t.Fatalf("round trip = %q, want %q", unescaped, original)
	}
}

// TestRenderJSONExportSorted proves the json export is one object with keys
// sorted, and that values are not escaped beyond JSON's own rules.
func TestRenderJSONExportSorted(t *testing.T) {
	secrets := map[string]string{
		"ZULU":  "last",
		"ALPHA": "first",
		"MIKE":  "with \"quotes\" and\nnewline",
	}
	got, err := renderJSONExport(secrets)
	if err != nil {
		t.Fatalf("renderJSONExport: %v", err)
	}
	want := `{"ALPHA":"first","MIKE":"with \"quotes\" and\nnewline","ZULU":"last"}`
	if string(got) != want {
		t.Fatalf("renderJSONExport = %s, want %s", got, want)
	}
	if strings.Index(string(got), "ALPHA") > strings.Index(string(got), "MIKE") {
		t.Fatal("keys are not sorted")
	}
}

// TestParseTTL pins the 1m..90d window and the unit set.
func TestParseTTL(t *testing.T) {
	valid := map[string]int64{
		"1m":  60,
		"30m": 1800,
		"12h": 43200,
		"7d":  604800,
		"90d": 7776000,
		"1s":  60, // 1s is below the floor only if under 60; 1s == 1 < 60, so it must fail (see invalid)
	}
	delete(valid, "1s")
	for spec, want := range valid {
		got, err := parseTTL(spec)
		if err != nil {
			t.Errorf("parseTTL(%q) errored: %v", spec, err)
			continue
		}
		if got != want {
			t.Errorf("parseTTL(%q) = %d, want %d", spec, got, want)
		}
	}
	invalid := []string{"", "0m", "91d", "30s", "7w", "d", "7", "-7d", "1.5h", "7D", "7 d"}
	for _, spec := range invalid {
		if _, err := parseTTL(spec); err == nil {
			t.Errorf("parseTTL(%q) accepted an out-of-range duration", spec)
		}
	}
}

// TestSlugValidation pins ^[a-z0-9][a-z0-9-]{0,62}$.
func TestSlugValidation(t *testing.T) {
	// "app-" is legal: the fixed pattern ^[a-z0-9][a-z0-9-]{0,62}$ permits a
	// trailing hyphen, and the spec's pattern is authoritative here.
	valid := []string{"a", "app", "my-app", "app2", "a1-b2-c3", "app-", strings.Repeat("a", 63)}
	for _, slug := range valid {
		if err := validateSlug("slug", slug); err != nil {
			t.Errorf("validateSlug(%q) = %v, want nil", slug, err)
		}
	}
	invalid := []string{"", "App", "-app", "_app", "app_1", "app/one", strings.Repeat("a", 64), "app one", "ápp"}
	for _, slug := range invalid {
		if err := validateSlug("slug", slug); err == nil {
			t.Errorf("validateSlug(%q) accepted an invalid slug", slug)
		}
	}
}

// TestSecretKeyValidation pins ^[A-Z_][A-Z0-9_]{0,127}$.
func TestSecretKeyValidation(t *testing.T) {
	valid := []string{"A", "_A", "DB_URL", "A1", "_", strings.Repeat("A", 128)}
	for _, key := range valid {
		if err := validateSecretKey(key); err != nil {
			t.Errorf("validateSecretKey(%q) = %v, want nil", key, err)
		}
	}
	invalid := []string{"", "a", "1A", "DB-URL", "DB URL", strings.Repeat("A", 129), "DÄTA"}
	for _, key := range invalid {
		if err := validateSecretKey(key); err == nil {
			t.Errorf("validateSecretKey(%q) accepted an invalid key", key)
		}
	}
}
