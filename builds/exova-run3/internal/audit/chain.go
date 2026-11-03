package audit

import "time"

// This file holds the chain's link primitives: what a stored row looks like once it
// is read back, and how its canonical bytes and hash are rebuilt from that row's own
// columns. The append path and the verify path both go through here, so there is
// exactly one definition of "the bytes that were hashed" in the whole service.
//
// The encoding itself is NOT reimplemented here. Canonical and Hash live in
// event.go, are frozen (docs/CONTRACTS.md §7), and are the only functions that
// produce canonical bytes. A second encoder in this package would drift from that
// one silently: both would produce valid JSON, the chain would still "verify", and
// every hash written before the drift would be wrong.

// StoredEvent is one audit_events row read back from the database: the event's
// fields plus the hash that was stored beside them.
//
// Event carries PrevHash as a field, but Canonical takes the previous hash as an
// argument because the same encoding is used to compute a hash that is not yet
// stored. A stored row is therefore self-describing: its canonical bytes are
// Canonical(e, e.PrevHash), rebuilt from the row's own columns and nothing else.
// There is deliberately no stored canonical blob to trust.
type StoredEvent struct {
	Event
	// Hash is audit_events.hash as stored: the lowercase hex SHA-256 that was
	// written when the row was appended.
	Hash string
}

// Canonical returns the canonical JSON bytes for the row, rebuilt from its own
// columns. This is the value that is hashed at verify time, and the reason a
// column-only tamper is detected: an edited target changes these bytes, so the
// recomputed hash no longer matches the stored one.
func (s StoredEvent) Canonical() []byte {
	return Canonical(s.Event, s.Event.PrevHash)
}

// ComputeHash returns the hash the row's own fields imply, given the row's own
// prev_hash. It is compared against Hash to detect a tampered column.
func (s StoredEvent) ComputeHash() string {
	return Hash(s.Event, s.Event.PrevHash)
}

// HashFor is the hash a new event would carry if appended with the given previous
// hash. The append path uses it; keeping it here means the writer and the verifier
// cannot disagree about what a row's hash should be.
func HashFor(e Event, prevHash string) string {
	return Hash(e, prevHash)
}

// Head is the audit_heads row for one scope, as read back.
//
// It is a CACHE of the chain's tail, never a source of truth. Present is false when
// no head row exists at all, which is the normal state of a scope that has never
// had an event, and also the state a deleted head leaves behind — the verifier
// distinguishes those two by whether any events exist.
type Head struct {
	Present bool
	Seq     int64
	Hash    string
}

// TruncateTimestamp returns t in the exact precision the chain commits to: UTC at
// microsecond resolution.
//
// This is load-bearing rather than cosmetic. FormatTimestamp truncates to the
// microsecond, but PostgreSQL's timestamptz ROUNDS to the microsecond when it
// stores a value. A caller that hands over a time with nanoseconds would therefore
// be hashed at the truncated value and stored at the rounded one — one microsecond
// apart — and every later verification of that row would recompute a different
// hash and report a tamper on a perfectly healthy database. Truncating once, before
// the hash is computed and before the row is written, makes the bytes hashed at
// write time and the bytes hashed from the row at verify time identical.
func TruncateTimestamp(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}
