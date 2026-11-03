package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		Scope:     "org_abc",
		Seq:       7,
		Timestamp: time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC),
		ActorID:   "usr_1",
		ActorKind: ActorUser,
		OrgID:     "org_abc",
		Action:    ActionSecretRead,
		Target:    "project/prj_1/env/env_1/key/API_KEY",
		SourceIP:  "203.0.113.9",
		Result:    ResultSuccess,
		PrevHash:  "abc123",
	}
}

func TestFormatTimestamp(t *testing.T) {
	// Microsecond precision, UTC, fixed width: nanoseconds are truncated because
	// timestamptz stores microseconds, and verify recomputes from the stored row.
	ts := time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)
	if got := FormatTimestamp(ts); got != "2026-03-04T05:06:07.123456Z" {
		t.Errorf("FormatTimestamp = %q, want 2026-03-04T05:06:07.123456Z", got)
	}

	// A zero-microsecond time must still be fixed width: RFC3339Nano would trim the
	// zeros and change the hash.
	ts = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if got := FormatTimestamp(ts); got != "2026-03-04T05:06:07.000000Z" {
		t.Errorf("FormatTimestamp = %q, want trailing zeros kept", got)
	}

	// A non-UTC time is converted, not formatted in place.
	loc := time.FixedZone("UTC+2", 2*60*60)
	ts = time.Date(2026, 3, 4, 7, 6, 7, 0, loc)
	if got := FormatTimestamp(ts); got != "2026-03-04T05:06:07.000000Z" {
		t.Errorf("FormatTimestamp = %q, want the UTC conversion", got)
	}
}

func TestCanonicalFieldOrder(t *testing.T) {
	got := string(Canonical(sampleEvent(), "abc123"))

	want := `{"scope":"org_abc","seq":7,"ts":"2026-03-04T05:06:07.123456Z","actor":"usr_1",` +
		`"actor_kind":"user","org":"org_abc","action":"secret.read",` +
		`"target":"project/prj_1/env/env_1/key/API_KEY","source_ip":"203.0.113.9",` +
		`"result":"success","prev_hash":"abc123"}`

	if got != want {
		t.Errorf("Canonical =\n%s\nwant\n%s", got, want)
	}
}

func TestCanonicalHasNoTrailingNewline(t *testing.T) {
	got := Canonical(sampleEvent(), "abc123")
	if strings.HasSuffix(string(got), "\n") {
		t.Error("Canonical ends with a newline; json.Encoder appends one")
	}
}

func TestCanonicalDisablesHTMLEscaping(t *testing.T) {
	event := sampleEvent()
	event.Target = `key/<A&B>`

	got := string(Canonical(event, "abc123"))
	if !strings.Contains(got, `<A&B>`) {
		t.Errorf("Canonical escaped HTML characters: %s", got)
	}
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u0026`) {
		t.Errorf("Canonical used HTML escapes: %s", got)
	}

	// A plain json.Marshal would escape; this asserts we are not using it.
	plain, err := json.Marshal(event.Target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `\u003c`) {
		t.Skip("encoding/json no longer escapes by default in this toolchain")
	}
}

func TestCanonicalIsDeterministic(t *testing.T) {
	event := sampleEvent()
	first := Canonical(event, "prev")
	second := Canonical(event, "prev")
	if string(first) != string(second) {
		t.Error("Canonical is not deterministic")
	}
}

func TestCanonicalUsesPrevHashArgument(t *testing.T) {
	event := sampleEvent()
	event.PrevHash = "ignored"

	// The prev hash comes from the argument, not the field: verify passes the stored
	// prev_hash of the row, and the writer passes the head it read.
	a := string(Canonical(event, "aaa"))
	b := string(Canonical(event, "bbb"))
	if a == b {
		t.Error("Canonical ignores the prevHash argument")
	}
	if !strings.Contains(a, `"prev_hash":"aaa"`) {
		t.Errorf("Canonical did not use the argument: %s", a)
	}
}

func TestHash(t *testing.T) {
	event := sampleEvent()
	prev := "abc123"

	got := Hash(event, prev)
	if len(got) != 64 {
		t.Fatalf("Hash length = %d, want 64 hex characters", len(got))
	}
	if got != strings.ToLower(got) {
		t.Error("Hash is not lowercase hex")
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("Hash is not hex: %v", err)
	}

	// hash = sha256(prev_hash_bytes || canonical)
	expected := sha256.Sum256(append([]byte(prev), Canonical(event, prev)...))
	if want := hex.EncodeToString(expected[:]); got != want {
		t.Errorf("Hash = %s, want %s", got, want)
	}
}

func TestHashDependsOnEveryField(t *testing.T) {
	base := sampleEvent()
	baseHash := Hash(base, "prev")

	mutations := map[string]func(*Event){
		"scope":      func(e *Event) { e.Scope = "org_other" },
		"seq":        func(e *Event) { e.Seq = 8 },
		"timestamp":  func(e *Event) { e.Timestamp = e.Timestamp.Add(time.Second) },
		"actor":      func(e *Event) { e.ActorID = "usr_2" },
		"actor_kind": func(e *Event) { e.ActorKind = ActorService },
		"org":        func(e *Event) { e.OrgID = "org_other" },
		"action":     func(e *Event) { e.Action = ActionSecretWrite },
		"target":     func(e *Event) { e.Target = "other" },
		"source_ip":  func(e *Event) { e.SourceIP = "198.51.100.1" },
		"result":     func(e *Event) { e.Result = ResultDenied },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			event := base
			mutate(&event)
			if Hash(event, "prev") == baseHash {
				t.Errorf("changing %s did not change the hash", name)
			}
		})
	}

	// And the prev hash itself.
	if Hash(base, "other") == baseHash {
		t.Error("changing the prev hash did not change the hash")
	}
}

func TestHashIgnoresTheUnusedPrevHashField(t *testing.T) {
	// Event.PrevHash is not part of the canonical form: the argument is. The writer
	// sets the field for the row, and verify rebuilds from the row's own column.
	a := sampleEvent()
	a.PrevHash = "field-a"
	b := sampleEvent()
	b.PrevHash = "field-b"

	if Hash(a, "same") != Hash(b, "same") {
		t.Error("the Event.PrevHash field affects the hash; it must not")
	}
}

func TestMicrosecondTruncationMatchesStoredRow(t *testing.T) {
	// The write path and the verify path must agree: a timestamp with nanoseconds
	// hashes the same as its microsecond truncation, because that is what PostgreSQL
	// stores.
	withNanos := sampleEvent()
	withNanos.Timestamp = time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)

	truncated := sampleEvent()
	truncated.Timestamp = time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.UTC)

	if Hash(withNanos, "prev") != Hash(truncated, "prev") {
		t.Error("a nanosecond timestamp hashes differently from its stored microsecond value")
	}
}

func TestActionNames(t *testing.T) {
	want := []string{
		"login.success", "login.failure", "logout",
		"secret.read", "secret.write", "secret.delete", "secret.rollback",
		"change.created", "change.approved", "change.rejected", "change.stale",
		"member.added", "member.removed", "member.role_changed",
		"grant.set", "grant.revoked",
		"token.issued", "token.revoked",
		"project.created", "environment.created",
		"organization.created", "organization.disabled",
		"denied",
		"masterkey.rotated",
	}

	if len(ActionNames) != len(want) {
		t.Fatalf("ActionNames has %d entries, want %d", len(ActionNames), len(want))
	}
	for i, action := range want {
		if ActionNames[i] != action {
			t.Errorf("ActionNames[%d] = %q, want %q", i, ActionNames[i], action)
		}
		if !IsKnownAction(action) {
			t.Errorf("IsKnownAction(%q) = false", action)
		}
	}

	for _, invented := range []string{"", "secret.list", "org.deleted", "login.success ", "SECRET.READ"} {
		if IsKnownAction(invented) {
			t.Errorf("IsKnownAction(%q) = true for an invented name", invented)
		}
	}
}

func TestConstants(t *testing.T) {
	if PlatformScope != "platform" {
		t.Errorf("PlatformScope = %q, want platform", PlatformScope)
	}
	if len(GenesisHash) != 64 {
		t.Errorf("GenesisHash length = %d, want 64", len(GenesisHash))
	}
	if strings.Trim(GenesisHash, "0") != "" {
		t.Errorf("GenesisHash = %q, want 32 zero bytes", GenesisHash)
	}

	results := []Result{ResultSuccess, ResultDenied, ResultFailed}
	wantResults := []string{"success", "denied", "failed"}
	for i, r := range results {
		if string(r) != wantResults[i] {
			t.Errorf("result %d = %q, want %q", i, r, wantResults[i])
		}
	}

	kinds := []ActorKind{ActorUser, ActorService, ActorPlatform, ActorAnonymous}
	wantKinds := []string{"user", "service", "platform", "anonymous"}
	for i, k := range kinds {
		if string(k) != wantKinds[i] {
			t.Errorf("actor kind %d = %q, want %q", i, k, wantKinds[i])
		}
	}
}

func TestNopWriter(t *testing.T) {
	var writer Writer = NopWriter()
	if _, err := writer.Append(t.Context(), sampleEvent()); err != nil {
		t.Errorf("NopWriter.Append: %v", err)
	}
}
