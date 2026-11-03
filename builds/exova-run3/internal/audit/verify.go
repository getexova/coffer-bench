package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// The verifier: the code that decides whether a chain is intact.
//
// The rules it is built on, and the reason each one matters:
//
//   - It walks audit_events from seq 1, in order, and rebuilds the canonical bytes
//     from EACH ROW'S OWN COLUMNS. It never trusts a stored canonical blob, because a
//     blob is one more thing an attacker can edit; and it never trusts a stored hash
//     alone, because the hash is the thing being checked. The row's columns are the
//     input, the recomputed hash is the test.
//
//   - It never trusts audit_heads. The head is a cache of the chain's tail. A
//     head/events disagreement is a finding in its own right, not a source of truth:
//     if verification took the head's word for where the chain ends, rewriting one
//     row of audit_heads would hide an arbitrary amount of deletion.
//
//   - It stops at the FIRST invalid sequence and reports it. Later damage is usually
//     a consequence of the first break — every subsequent prev_hash link is wrong
//     once one row changes — so reporting the whole cascade would bury the one
//     number an operator can act on.
//
//   - It modifies nothing. There is no write path in this file, and the runtime role
//     cannot UPDATE or DELETE audit_events anyway. Verification is safe to run
//     against a live database, from a read replica, and from a restored dump.
//
// The residual case, stated plainly because it is the one thing this cannot detect:
// an attacker who can rewrite audit_heads can truncate audit_events and then set the
// head to the new tail. The result is internally consistent — every remaining row
// links correctly and the head matches the last row — so it verifies as valid. The
// only control against that is a copy of the chain the attacker does not hold: an
// off-box backup, compared against the live chain. That is why the backup is the real
// control and this check is a detection aid, not a guarantee. Note that rewriting the
// head alone does NOT hide a truncation that leaves a gap or a broken link, and
// truncating without also rewriting the head is caught here as "events shorter than
// head" (truncation) or "events ahead of head" (tampering).

// scanBatchSize is how many rows the verifier reads per query. It bounds memory on a
// chain of millions of events without making one round trip per row.
const scanBatchSize = 500

// FindingKind names what is wrong with a chain. Each kind is distinct because each
// one means something different to an operator: a hash mismatch is a column edit, a
// gap is a deleted row, events behind the head is a truncation, and events ahead of
// the head is an append that bypassed the head lock.
type FindingKind string

const (
	// FindingNone means no finding: the chain is valid.
	FindingNone FindingKind = ""

	// FindingHashMismatch means a row's stored hash is not the hash its own columns
	// imply. A column was edited — target, actor, timestamp, anything — and the hash
	// was not (or could not be) recomputed consistently.
	FindingHashMismatch FindingKind = "hash_mismatch"

	// FindingMissingSeq means a sequence number is absent from the middle of the
	// chain: a row was deleted, or an append skipped a number.
	FindingMissingSeq FindingKind = "missing_seq"

	// FindingPrevHashMismatch means a row's prev_hash is not the previous row's hash,
	// so the chain does not link. This catches a row inserted into the middle of the
	// chain, and a rewritten first row whose prev_hash is no longer the genesis hash.
	FindingPrevHashMismatch FindingKind = "prev_hash_mismatch"

	// FindingOutOfOrder means the rows did not arrive in strictly ascending sequence
	// order, which the primary key makes impossible unless the read itself is wrong.
	FindingOutOfOrder FindingKind = "out_of_order"

	// FindingMalformedHash means a hash column is not 64 lowercase hex characters,
	// so it is not a SHA-256 this service ever wrote.
	FindingMalformedHash FindingKind = "malformed_hash"

	// FindingEventsAheadOfHead means the events reach further than the head says they
	// do. Appends and the head update are one transaction, so this cannot happen by
	// crash: it is an append that bypassed the head lock, or a head row rolled back.
	FindingEventsAheadOfHead FindingKind = "events_ahead_of_head"

	// FindingEventsBehindHead means the head describes more events than exist. That
	// is truncation: rows were deleted from the end, or the whole scope was emptied.
	FindingEventsBehindHead FindingKind = "events_behind_head"

	// FindingHeadMismatch means the head's sequence matches the tail but its hash is
	// not the tail row's hash: the head was rewritten to something that does not
	// describe the chain.
	FindingHeadMismatch FindingKind = "head_mismatch"

	// FindingHeadMissing means events exist for a scope with no head row at all. The
	// next append would recreate the head at seq 0 and collide with the existing
	// rows, so the chain cannot continue until this is resolved.
	FindingHeadMissing FindingKind = "head_missing"
)

// Verdict is the outcome of verifying one scope.
type Verdict struct {
	// Valid is true only when the whole chain was walked with no finding.
	Valid bool
	// FirstInvalidSeq is the offending sequence number, and is meaningful only when
	// Valid is false. It is 0 when the chain is valid.
	FirstInvalidSeq int64
	// Kind is the finding. FindingNone when Valid.
	Kind FindingKind
	// Detail is a human-readable explanation for the server log and the audit event.
	// It never reaches the API body, which is fixed at {valid, first_invalid_seq}.
	Detail string
	// Scope is the chain that was verified.
	Scope string
	// Events is how many rows were walked, and TailSeq/TailHash describe the last one.
	// They are reported so an operator can see what the check actually covered.
	Events   int64
	TailSeq  int64
	TailHash string
}

// FirstInvalid returns the offending sequence as an optional value, which is the
// shape §7.2 fixes: a number when the chain is invalid, null when it is valid.
func (v Verdict) FirstInvalid() *int64 {
	if v.Valid {
		return nil
	}
	seq := v.FirstInvalidSeq
	return &seq
}

// Describe renders the verdict as one line for a log or an audit event. It never
// contains an event's target, actor or any other caller-supplied value: a tampered
// row is exactly the row whose contents should not be copied into a log line.
func (v Verdict) Describe() string {
	if v.Valid {
		return fmt.Sprintf("audit chain %q is valid: %d events, tail seq %d", v.Scope, v.Events, v.TailSeq)
	}
	return fmt.Sprintf("audit chain %q is INVALID at seq %d: %s (%s); %d events walked before the finding",
		v.Scope, v.FirstInvalidSeq, v.Kind, v.Detail, v.Events)
}

// EventScanner is the read side the verifier needs. It is a narrow interface so the
// verification algorithm can be tested against an in-memory chain — including a
// tampered one — without a database, which is the only way to prove the walk itself
// is correct independently of the SQL.
//
// auditq.Store implements it.
type EventScanner interface {
	// ScanScope returns up to limit rows with seq > afterSeq, ordered by seq
	// ascending. It must not skip or reorder rows: the verifier's gap detection
	// depends on seeing every row that exists.
	ScanScope(ctx context.Context, scope string, afterSeq int64, limit int) ([]StoredEvent, error)
	// Head returns the scope's audit_heads row, with Present false when there is none.
	Head(ctx context.Context, scope string) (Head, error)
}

// ErrNoScanner is returned when Verify is called without a read source.
var ErrNoScanner = errors.New("audit: no event scanner")

// Verify walks the chain for scope and reports the first invalid sequence.
//
// An error means verification could not be performed — the database was unreachable,
// a query failed. An intact-but-invalid chain is NOT an error: it is a Verdict with
// Valid false. That distinction is deliberate, because a caller must be able to tell
// "I could not check" (a 500, worth retrying) from "I checked and the chain is
// broken" (a 200 with valid:false, a fact about the data).
func Verify(ctx context.Context, scanner EventScanner, scope string) (Verdict, error) {
	if scanner == nil {
		return Verdict{}, ErrNoScanner
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if scope == "" {
		return Verdict{}, errors.New("audit: verify needs a scope")
	}

	verdict := Verdict{Valid: true, Scope: scope}

	// The first row of a scope links to the genesis hash, so the walk starts there.
	// An attacker who rewrites row 1's prev_hash to break the link to nothing is
	// caught here, because the expected value is fixed rather than read from the row.
	expectedSeq := int64(1)
	expectedPrev := GenesisHash

	for {
		batch, err := scanner.ScanScope(ctx, scope, expectedSeq-1, scanBatchSize)
		if err != nil {
			return Verdict{}, fmt.Errorf("audit: could not read the chain: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		for _, row := range batch {
			// Sequence continuity. A row that is not the one we expect means either
			// a hole (row.Seq > expectedSeq: a deletion) or a repeat (row.Seq <
			// expectedSeq: an impossible duplicate, but a read that returned one is
			// not a read the verifier can trust).
			if row.Seq < expectedSeq {
				return invalidVerdict(verdict, row.Seq, FindingOutOfOrder,
					fmt.Sprintf("row seq %d arrived after seq %d", row.Seq, expectedSeq-1)), nil
			}
			if row.Seq > expectedSeq {
				return invalidVerdict(verdict, expectedSeq, FindingMissingSeq,
					fmt.Sprintf("seq %d is absent; the chain resumes at %d", expectedSeq, row.Seq)), nil
			}

			// Linkage. The expected previous hash is the one the PREVIOUS ROW carried,
			// tracked by this loop, and never the value the row claims about itself.
			if row.PrevHash != expectedPrev {
				return invalidVerdict(verdict, row.Seq, FindingPrevHashMismatch,
					fmt.Sprintf("prev_hash does not match the hash of seq %d", row.Seq-1)), nil
			}

			// The stored hash must be the shape this service writes, before it is
			// compared to anything: a hash column replaced with junk is a different
			// finding from a hash that is well formed but wrong.
			if !isHexHash(row.Hash) {
				return invalidVerdict(verdict, row.Seq, FindingMalformedHash,
					"the stored hash is not 64 lowercase hex characters"), nil
			}

			// The check the whole chain rests on: recompute the hash from this row's
			// own columns and compare. This is what catches an edited target, actor,
			// timestamp or result, including an edit that also rewrote the hash
			// column to match — the next row's prev_hash, and the head, no longer
			// agree, and either of those is reported.
			if got := row.ComputeHash(); got != row.Hash {
				return invalidVerdict(verdict, row.Seq, FindingHashMismatch,
					"the stored hash is not the hash the row's own columns imply"), nil
			}

			expectedPrev = row.Hash
			expectedSeq = row.Seq + 1
			verdict.Events++
			verdict.TailSeq = row.Seq
			verdict.TailHash = row.Hash
		}

		if len(batch) < scanBatchSize {
			break
		}
	}

	// The events are internally consistent from seq 1. Now check the cache against
	// what was actually walked. The head is checked LAST, on purpose: a head finding
	// is only meaningful once the events themselves are known to be sound, otherwise
	// the event-level finding is the one worth reporting.
	head, err := scanner.Head(ctx, scope)
	if err != nil {
		return Verdict{}, fmt.Errorf("audit: could not read the head: %w", err)
	}

	if verdict.Events == 0 {
		// No events at all. The only consistent head is absent or seq 0.
		if head.Present && head.Seq != 0 {
			// The head remembers events that are not there: truncation of the whole
			// scope. The first sequence that should exist and does not is 1.
			return invalidVerdict(verdict, 1, FindingEventsBehindHead,
				fmt.Sprintf("the head records seq %d but the scope holds no events", head.Seq)), nil
		}
		if head.Present && head.Seq == 0 && head.Hash != "" && head.Hash != GenesisHash {
			return invalidVerdict(verdict, 0, FindingHeadMismatch,
				"the head is at seq 0 but carries a hash that is not the genesis hash"), nil
		}
		return verdict, nil
	}

	if !head.Present {
		return invalidVerdict(verdict, 1, FindingHeadMissing,
			fmt.Sprintf("%d events exist but the scope has no head row", verdict.Events)), nil
	}

	switch {
	case head.Seq > verdict.TailSeq:
		// The head claims more events than exist: the tail was deleted. The first
		// missing sequence is the one after the last row that survived.
		return invalidVerdict(verdict, verdict.TailSeq+1, FindingEventsBehindHead,
			fmt.Sprintf("the head records seq %d but the chain ends at seq %d", head.Seq, verdict.TailSeq)), nil
	case head.Seq < verdict.TailSeq:
		// The events reach past the head: an append that did not advance it. The first
		// event the head does not account for is the one after its sequence.
		return invalidVerdict(verdict, head.Seq+1, FindingEventsAheadOfHead,
			fmt.Sprintf("the chain reaches seq %d but the head records only seq %d", verdict.TailSeq, head.Seq)), nil
	case head.Hash != verdict.TailHash:
		return invalidVerdict(verdict, verdict.TailSeq, FindingHeadMismatch,
			fmt.Sprintf("the head's hash does not match the hash recomputed for seq %d", verdict.TailSeq)), nil
	}

	return verdict, nil
}

// invalidVerdict records the finding and stops the walk.
func invalidVerdict(v Verdict, seq int64, kind FindingKind, detail string) Verdict {
	v.Valid = false
	v.FirstInvalidSeq = seq
	v.Kind = kind
	v.Detail = detail
	return v
}

// LogFinding writes the verdict to a structured log line at a level that matches the
// outcome: a broken chain is an ERROR, because someone needs to act on it, while a
// valid chain is INFO.
//
// The error line is built to be alertable rather than read by a human first: it
// carries a stable `event` marker (`audit_chain_invalid`), the machine-readable
// `finding` kind and the numeric `first_invalid_seq`, so an alerting rule can match on
// the marker and route on the kind without parsing prose. `detail` is for the person
// who arrives afterwards, and it never contains a row's caller-supplied fields — a
// tampered row is exactly the row whose contents must not be copied into a log line.
//
// This log line is the sink for an integrity finding. It is deliberately not an audit
// event: the frozen action list (docs/CONTRACTS.md §3) has no action for an
// audit-integrity finding, and appending to the chain that was just proved broken is
// unsound. See docs/DECISIONS.md for the reserved out-of-band action name.
func (v Verdict) LogFinding(log *slog.Logger) {
	if log == nil {
		return
	}
	if v.Valid {
		log.Info("audit chain verified",
			"event", "audit_chain_valid",
			"scope", v.Scope,
			"events", v.Events,
			"tail_seq", v.TailSeq,
		)
		return
	}
	log.Error("audit chain verification failed",
		"event", "audit_chain_invalid",
		"scope", v.Scope,
		"finding", string(v.Kind),
		"first_invalid_seq", v.FirstInvalidSeq,
		"events_walked", v.Events,
		"tail_seq", v.TailSeq,
		"detail", v.Detail,
	)
}
