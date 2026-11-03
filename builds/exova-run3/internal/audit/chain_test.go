package audit_test

// These tests are pure: no database, no clock, no network. They pin the properties
// that a compiler cannot check — canonical byte layout, hash linkage, and the
// verifier's walk — because a chain that verifies when it should not is worse than
// one that fails.

import (
	"context"
	"strings"
	"testing"
	"time"

	"coffer/internal/audit"
)

// handWorkedEvent is the event whose hash was computed by hand, outside this code,
// with `printf '%s%s' "$GENESIS" "$CANONICAL" | sha256sum`. It is the anchor for
// every other claim about the encoding: if this test fails, either the canonical
// form changed (which needs a canon_version and a migration, docs/CONTRACTS.md §7) or
// the hash input changed.
func handWorkedEvent() audit.Event {
	ts, err := time.Parse("2006-01-02T15:04:05.000000Z", "2026-01-16T09:41:07.123456Z")
	if err != nil {
		panic("test: the hand-worked timestamp does not parse: " + err.Error())
	}
	return audit.Event{
		Scope:     "org_abc123",
		Seq:       1,
		Timestamp: ts,
		ActorID:   "user_0001",
		ActorKind: audit.ActorUser,
		OrgID:     "org_abc123",
		Action:    audit.ActionSecretRead,
		Target:    "project/p1/env/e1/key/API_KEY",
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
		PrevHash:  audit.GenesisHash,
	}
}

// handWorkedCanonical is the exact 312-byte canonical JSON, transcribed from the
// shell command. It is written out literally rather than built from a struct so that
// a change to the field order or a field name fails here, loudly, instead of silently
// invalidating every hash ever written.
const handWorkedCanonical = `{"scope":"org_abc123","seq":1,"ts":"2026-01-16T09:41:07.123456Z","actor":"user_0001","actor_kind":"user","org":"org_abc123","action":"secret.read","target":"project/p1/env/e1/key/API_KEY","source_ip":"203.0.113.7","result":"success","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}`

// handWorkedHash is sha256(genesis_ascii_bytes || handWorkedCanonical), lowercase hex.
const handWorkedHash = "76bfe8044cabe9e763035693a07b4519946cd35f246f9a62d1a1476faca999d3"

// TestHandWorkedCanonicalBytes proves the canonical form is byte-for-byte the one
// computed on paper.
func TestHandWorkedCanonicalBytes(t *testing.T) {
	got := string(audit.Canonical(handWorkedEvent(), audit.GenesisHash))
	if got != handWorkedCanonical {
		t.Fatalf("canonical bytes differ from the hand-worked value\n got: %s\nwant: %s", got, handWorkedCanonical)
	}
	if len(got) != 312 {
		t.Fatalf("canonical length is %d bytes, expected 312", len(got))
	}
	// The newline json.Encoder appends must not be part of the hash input.
	if strings.HasSuffix(got, "\n") {
		t.Fatal("canonical bytes end with a newline; the hash input must not include it")
	}
}

// TestHandWorkedHash proves the hash is the one computed on paper.
func TestHandWorkedHash(t *testing.T) {
	got := audit.Hash(handWorkedEvent(), audit.GenesisHash)
	if got != handWorkedHash {
		t.Fatalf("hash differs from the hand-worked value\n got: %s\nwant: %s", got, handWorkedHash)
	}
}

// TestHashCoversEveryField proves no field is silently outside the hash. Each field
// is changed in turn and the hash must move; a field that does not move the hash is a
// field an attacker can edit without detection.
func TestHashCoversEveryField(t *testing.T) {
	base := handWorkedEvent()
	baseline := audit.Hash(base, base.PrevHash)

	cases := []struct {
		name   string
		mutate func(*audit.Event)
	}{
		{"scope", func(e *audit.Event) { e.Scope = "org_other" }},
		{"seq", func(e *audit.Event) { e.Seq = 2 }},
		{"timestamp", func(e *audit.Event) { e.Timestamp = e.Timestamp.Add(time.Second) }},
		{"actor", func(e *audit.Event) { e.ActorID = "user_0002" }},
		{"actor_kind", func(e *audit.Event) { e.ActorKind = audit.ActorService }},
		{"org", func(e *audit.Event) { e.OrgID = "org_other" }},
		{"action", func(e *audit.Event) { e.Action = audit.ActionSecretWrite }},
		{"target", func(e *audit.Event) { e.Target = "project/p1/env/e1/key/OTHER" }},
		{"source_ip", func(e *audit.Event) { e.SourceIP = "198.51.100.9" }},
		{"result", func(e *audit.Event) { e.Result = audit.ResultDenied }},
		{"prev_hash", func(e *audit.Event) { e.PrevHash = strings.Repeat("a", 64) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			if got := audit.Hash(mutated, mutated.PrevHash); got == baseline {
				t.Fatalf("changing %s did not change the hash; that field is not covered by the chain", tc.name)
			}
		})
	}
}

// TestTimestampPrecisionIsStable is the round-trip guard. A timestamp with
// sub-microsecond digits must hash identically to its truncated form, because
// timestamptz stores microseconds. Without this, an event written from time.Now()
// would verify as tampered.
func TestTimestampPrecisionIsStable(t *testing.T) {
	base := handWorkedEvent()
	// 123456789ns = 123456.789us: PostgreSQL would store 123457 (it rounds), so the
	// writer must truncate to 123456 before hashing. Both the truncated and the
	// untruncated value must therefore produce the same canonical bytes.
	base.Timestamp = base.Timestamp.Add(789 * time.Nanosecond)

	truncated := base
	truncated.Timestamp = audit.TruncateTimestamp(truncated.Timestamp)

	if got, want := audit.Canonical(truncated, truncated.PrevHash), audit.Canonical(handWorkedEvent(), audit.GenesisHash); string(got) != string(want) {
		t.Fatalf("a sub-microsecond timestamp did not canonicalise to the truncated form\n got: %s\nwant: %s", got, want)
	}
	if got, want := audit.Hash(truncated, truncated.PrevHash), handWorkedHash; got != want {
		t.Fatalf("sub-microsecond timestamp changed the hash\n got: %s\nwant: %s", got, want)
	}
	if got := audit.FormatTimestamp(base.Timestamp.UTC()); !endsInMicrosecondZ(got) {
		t.Fatalf("FormatTimestamp rendered %q, expected six fractional digits and a Z", got)
	}
}

// endsInMicrosecondZ reports whether s ends in exactly six fractional digits
// followed by "Z", which is the canonical timestamp layout.
//
// "2026-01-16T09:41:07.123456Z" is 27 characters: the '.' is at len-8 and the six
// digits occupy len-7 .. len-2, with 'Z' at len-1.
func endsInMicrosecondZ(s string) bool {
	if len(s) < 8 || s[len(s)-1] != 'Z' || s[len(s)-8] != '.' {
		return false
	}
	for _, c := range s[len(s)-7 : len(s)-1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// --- in-memory chain, for the verifier's walk ----------------------------------

// memScanner is an in-memory audit.EventScanner. It lets the verification algorithm
// be tested against chains that no honest writer could produce — including a
// tampered one — which is the only way to prove the walk itself is right,
// independently of the SQL that feeds it.
type memScanner struct {
	rows []audit.StoredEvent
	head audit.Head
	err  error
}

func (m *memScanner) ScanScope(_ context.Context, _ string, afterSeq int64, limit int) ([]audit.StoredEvent, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []audit.StoredEvent
	for _, r := range m.rows {
		if r.Seq > afterSeq {
			out = append(out, r)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (m *memScanner) Head(_ context.Context, _ string) (audit.Head, error) {
	if m.err != nil {
		return audit.Head{}, m.err
	}
	return m.head, nil
}

// buildChain produces a valid chain of n events for one scope, exactly as the writer
// would: each hash covers the previous row's hash.
func buildChain(n int) []audit.StoredEvent {
	rows := make([]audit.StoredEvent, 0, n)
	prev := audit.GenesisHash
	ts := time.Date(2026, 1, 16, 9, 41, 7, 123456000, time.UTC)

	for i := 1; i <= n; i++ {
		e := audit.Event{
			Scope:     "org_abc123",
			Seq:       int64(i),
			Timestamp: ts.Add(time.Duration(i) * time.Second),
			ActorID:   "user_0001",
			ActorKind: audit.ActorUser,
			OrgID:     "org_abc123",
			Action:    audit.ActionSecretRead,
			Target:    "project/p1/env/e1/key/KEY_" + string(rune('A'+i-1)),
			SourceIP:  "203.0.113.7",
			Result:    audit.ResultSuccess,
			PrevHash:  prev,
		}
		hash := audit.Hash(e, prev)
		rows = append(rows, audit.StoredEvent{Event: e, Hash: hash})
		prev = hash
	}
	return rows
}

func headOf(rows []audit.StoredEvent) audit.Head {
	if len(rows) == 0 {
		return audit.Head{Present: false}
	}
	last := rows[len(rows)-1]
	return audit.Head{Present: true, Seq: last.Seq, Hash: last.Hash}
}

// TestVerifyCleanChain: a well-formed chain verifies, and the verdict reports the
// tail it actually walked.
func TestVerifyCleanChain(t *testing.T) {
	rows := buildChain(5)
	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify returned an error for a clean chain: %v", err)
	}
	if !v.Valid {
		t.Fatalf("a clean chain did not verify: %s", v.Describe())
	}
	if v.FirstInvalid() != nil {
		t.Fatalf("a valid verdict must report first_invalid_seq as nil, got %d", *v.FirstInvalid())
	}
	if v.Events != 5 || v.TailSeq != 5 || v.TailHash != rows[4].Hash {
		t.Fatalf("verdict reports events=%d tail_seq=%d, expected 5/5", v.Events, v.TailSeq)
	}
}

// TestVerifyEmptyChain: a scope with no events and no head is valid, not an error.
// Every organization starts here.
func TestVerifyEmptyChain(t *testing.T) {
	v, err := audit.Verify(context.Background(), &memScanner{}, "org_new")
	if err != nil {
		t.Fatalf("Verify errored on an empty scope: %v", err)
	}
	if !v.Valid {
		t.Fatalf("an empty scope must verify: %s", v.Describe())
	}
}

// TestVerifyHashMismatch: editing a column without touching the hash is the plain
// tamper. It must report that exact seq and stop.
func TestVerifyHashMismatch(t *testing.T) {
	rows := buildChain(5)
	rows[1].Target = "project/p1/env/e1/key/TAMPERED" // seq 2

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.FirstInvalidSeq != 2 || v.Kind != audit.FindingHashMismatch {
		t.Fatalf("expected hash_mismatch at seq 2, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyHashRewrittenToMatchTamper: an attacker who edits BOTH the target and the
// hash column is caught by the next row's prev_hash link, and by the head. This is
// the case that a verifier trusting a stored blob or a stored hash would miss.
func TestVerifyHashRewrittenToMatchTamper(t *testing.T) {
	rows := buildChain(5)
	rows[1].Target = "project/p1/env/e1/key/TAMPERED"
	rows[1].Hash = rows[1].ComputeHash() // recompute so the row is self-consistent

	// Row 2's own hash is now correct for its own columns, but row 3 still points at
	// the OLD row-2 hash, so the break surfaces at seq 3.
	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid {
		t.Fatal("a row edited together with its own hash verified as valid; the prev_hash link is not being checked")
	}
	if v.FirstInvalidSeq != 3 || v.Kind != audit.FindingPrevHashMismatch {
		t.Fatalf("expected prev_hash_mismatch at seq 3, got seq=%d kind=%s", v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyLastRowHashRewritten: if the LAST row is edited together with its hash and
// the head is not, only the head check can catch it.
func TestVerifyLastRowHashRewritten(t *testing.T) {
	rows := buildChain(5)
	rows[4].Target = "project/p1/env/e1/key/TAMPERED"
	rows[4].Hash = rows[4].ComputeHash()

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(buildChain(5))}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid {
		t.Fatal("a rewritten last row verified as valid; the head hash is not being compared")
	}
	if v.FirstInvalidSeq != 5 || v.Kind != audit.FindingHeadMismatch {
		t.Fatalf("expected head_mismatch at seq 5, got seq=%d kind=%s", v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyGap: a deleted middle row is reported at the sequence that should exist.
func TestVerifyGap(t *testing.T) {
	rows := buildChain(5)
	rows = append(rows[:2], rows[3:]...) // drop seq 3

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(buildChain(5))}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.FirstInvalidSeq != 3 || v.Kind != audit.FindingMissingSeq {
		t.Fatalf("expected missing_seq at seq 3, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyPrevHashBreak: a row whose prev_hash is not its predecessor's hash, with
// a gap-free sequence, is a spliced chain.
func TestVerifyPrevHashBreak(t *testing.T) {
	rows := buildChain(5)
	rows[2].PrevHash = strings.Repeat("b", 64) // seq 3

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.FirstInvalidSeq != 3 || v.Kind != audit.FindingPrevHashMismatch {
		t.Fatalf("expected prev_hash_mismatch at seq 3, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyFirstRowMustLinkToGenesis: rewriting row 1's prev_hash to anything but the
// genesis hash is caught, because the expected value is the constant, not the row.
func TestVerifyFirstRowMustLinkToGenesis(t *testing.T) {
	rows := buildChain(3)
	rows[0].PrevHash = strings.Repeat("c", 64)
	rows[0].Hash = rows[0].ComputeHash() // self-consistent, so only the genesis link can catch it

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.FirstInvalidSeq != 1 || v.Kind != audit.FindingPrevHashMismatch {
		t.Fatalf("expected prev_hash_mismatch at seq 1, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyEventsBehindHead: rows deleted from the tail. The head remembers more
// events than exist, which is truncation.
func TestVerifyEventsBehindHead(t *testing.T) {
	full := buildChain(5)
	truncated := full[:3] // seq 1..3 survive, head still says 5

	v, err := audit.Verify(context.Background(), &memScanner{rows: truncated, head: headOf(full)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingEventsBehindHead {
		t.Fatalf("expected events_behind_head, got valid=%v kind=%s", v.Valid, v.Kind)
	}
	if v.FirstInvalidSeq != 4 {
		t.Fatalf("expected the first missing sequence to be 4, got %d", v.FirstInvalidSeq)
	}
}

// TestVerifyEntireScopeTruncated: every row deleted but the head survives. The first
// sequence that should exist is 1.
func TestVerifyEntireScopeTruncated(t *testing.T) {
	head := headOf(buildChain(3))

	v, err := audit.Verify(context.Background(), &memScanner{head: head}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingEventsBehindHead || v.FirstInvalidSeq != 1 {
		t.Fatalf("expected events_behind_head at seq 1, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyEventsAheadOfHead: events past the head. Because append and the head
// update are one transaction, this cannot be a crash; it is tampering.
func TestVerifyEventsAheadOfHead(t *testing.T) {
	full := buildChain(5)
	head := headOf(full[:3]) // head rolled back to seq 3

	v, err := audit.Verify(context.Background(), &memScanner{rows: full, head: head}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingEventsAheadOfHead {
		t.Fatalf("expected events_ahead_of_head, got valid=%v kind=%s", v.Valid, v.Kind)
	}
	if v.FirstInvalidSeq != 4 {
		t.Fatalf("expected the first unaccounted sequence to be 4, got %d", v.FirstInvalidSeq)
	}
}

// TestVerifyHeadRewrittenToWrongHash: the head's seq matches the tail but its hash is
// not the tail's hash.
func TestVerifyHeadRewrittenToWrongHash(t *testing.T) {
	rows := buildChain(4)
	head := headOf(rows)
	head.Hash = strings.Repeat("d", 64)

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: head}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingHeadMismatch || v.FirstInvalidSeq != 4 {
		t.Fatalf("expected head_mismatch at seq 4, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyHeadMissing: events with no head row. The next append would recreate the
// head at seq 0 and collide, so this must not read as valid.
func TestVerifyHeadMissing(t *testing.T) {
	rows := buildChain(2)

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: audit.Head{Present: false}}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingHeadMissing || v.FirstInvalidSeq != 1 {
		t.Fatalf("expected head_missing at seq 1, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyMalformedHash: a hash column replaced with something that is not a
// SHA-256 this service wrote.
func TestVerifyMalformedHash(t *testing.T) {
	rows := buildChain(3)
	rows[1].Hash = "not-a-hash"

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.Valid || v.Kind != audit.FindingMalformedHash || v.FirstInvalidSeq != 2 {
		t.Fatalf("expected malformed_hash at seq 2, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
	}
}

// TestVerifyStopsAtFirstInvalid: damage at seq 2 and seq 4 must report 2, not 4 and
// not both. The first break explains the rest.
func TestVerifyStopsAtFirstInvalid(t *testing.T) {
	rows := buildChain(5)
	rows[1].Target = "tampered-2"
	rows[3].Target = "tampered-4"

	v, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if v.FirstInvalidSeq != 2 {
		t.Fatalf("expected the first invalid sequence to be 2, got %d", v.FirstInvalidSeq)
	}
}

// TestVerifyHeadRewrittenToMatchTruncation documents the residual case, and is the
// reason the off-box backup is the real control rather than this check.
//
// If an attacker can rewrite audit_heads AND delete the tail, the result is
// internally consistent: every remaining row links correctly and the head matches the
// last row. Verification reports it VALID, because nothing in the database disagrees
// with anything else. Only a copy of the chain the attacker does not hold — a backup,
// compared against the live chain — can reveal it.
//
// This test asserts the limitation rather than pretending it does not exist, so the
// behaviour is a documented property of the verifier and not a surprise during an
// incident.
func TestVerifyHeadRewrittenToMatchTruncationIsUndetectable(t *testing.T) {
	full := buildChain(5)
	truncated := full[:3]

	// The attacker truncates the event table and then rewrites the head to describe
	// the shortened chain.
	rewrittenHead := headOf(truncated)

	v, err := audit.Verify(context.Background(), &memScanner{rows: truncated, head: rewrittenHead}, "org_abc123")
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if !v.Valid {
		t.Fatalf("expected the residual case to verify as valid (this is the documented limitation), got: %s", v.Describe())
	}
	// What still distinguishes it from a genuine chain: the event count. An operator
	// comparing against a backup sees 3 where the backup recorded 5.
	if v.Events != 3 {
		t.Fatalf("expected 3 events walked, got %d", v.Events)
	}
}

// TestVerifyScannerErrorIsAnError: "I could not check" must not be reported as
// "the chain is broken". The distinction is what lets the handler answer 500 vs 200.
func TestVerifyScannerErrorIsAnError(t *testing.T) {
	_, err := audit.Verify(context.Background(), &memScanner{err: context.DeadlineExceeded}, "org_abc123")
	if err == nil {
		t.Fatal("a scanner failure must be returned as an error, not as an invalid verdict")
	}
}

// TestVerifyNeedsScannerAndScope guards the two programming errors.
func TestVerifyNeedsScannerAndScope(t *testing.T) {
	if _, err := audit.Verify(context.Background(), nil, "org_abc123"); err == nil {
		t.Fatal("Verify with no scanner must error")
	}
	rows := buildChain(1)
	if _, err := audit.Verify(context.Background(), &memScanner{rows: rows, head: headOf(rows)}, ""); err == nil {
		t.Fatal("Verify with no scope must error")
	}
}

// TestCanonicalRebuiltFromColumnsNotBlob is the property that catches a column-only
// tamper: a row's canonical bytes come from its own columns, so an edited target
// changes the bytes and therefore the hash.
func TestCanonicalRebuiltFromColumnsNotBlob(t *testing.T) {
	rows := buildChain(1)
	original := rows[0]

	edited := original
	edited.Target = "project/p1/env/e1/key/SOMETHING_ELSE"

	if string(edited.Canonical()) == string(original.Canonical()) {
		t.Fatal("changing a column did not change the canonical bytes; the hash would not detect the edit")
	}
	if edited.ComputeHash() == original.Hash {
		t.Fatal("changing a column did not change the recomputed hash")
	}
}

// TestVerdictFirstInvalidIsNullWhenValid pins the §7.2 response shape at the type
// level: a valid verdict must serialise first_invalid_seq as null, never as 0.
func TestVerdictFirstInvalidIsNullWhenValid(t *testing.T) {
	valid := audit.Verdict{Valid: true}
	if valid.FirstInvalid() != nil {
		t.Fatal("a valid verdict must return nil, so the API emits null rather than 0")
	}
	invalid := audit.Verdict{Valid: false, FirstInvalidSeq: 7}
	got := invalid.FirstInvalid()
	if got == nil || *got != 7 {
		t.Fatalf("an invalid verdict must return the offending seq, got %v", got)
	}
}
