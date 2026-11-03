package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/store"
)

// The append path: the only code in Coffer that writes audit state.
//
// One append is one transaction and three statements, and the ordering is the whole
// correctness argument:
//
//	1. ensure the scope's head row exists (INSERT ... ON CONFLICT DO NOTHING)
//	2. SELECT seq, hash FROM audit_heads WHERE scope = $1 FOR UPDATE   <- the lock
//	3. INSERT INTO audit_events
//	4. UPDATE audit_heads SET seq = $2, hash = $3
//
// Step 2 is what serialises appends per chain. A chain is per scope, so two
// organizations never wait on each other, and two appends to one organization always
// produce a gapless sequence.
//
// Steps 3 and 4 MUST be in the same transaction as each other and as the lock. If
// they were separate, a crash between them would leave events ahead of the head, and
// verification — which must treat a head/events disagreement as tampering — would
// raise a false alarm on a healthy database and on every restore taken from it.
// Because they are atomic, a disagreement can only mean tampering.

// LockTimeout bounds how long an append waits for a chain's head lock.
//
// A stuck head lock is a bug or a pathological writer, never something a request
// should hang on: the caller's own deadline may be minutes away, and an audit append
// holding a connection for that long takes the pool down with it. Timing out is a
// failed append, which the caller reports and retries; it never corrupts the chain,
// because nothing was written.
const LockTimeout = 5 * time.Second

// Errors returned by the append path. A caller should not need to tell them apart —
// every one of them means the event was not recorded — but they are distinct values
// so a test can assert on the reason rather than on message text.
var (
	// ErrInvalidEvent is a programming error in the caller: the event could not be
	// stored as given. It is never a reason to write something approximate.
	ErrInvalidEvent = errors.New("audit: invalid event")
	// ErrNoDatabase is an Appender with no pool.
	ErrNoDatabase = errors.New("audit: no database")
)

// EventError explains why an event was rejected. Field names the offending field and
// never carries its value, so an error log line cannot become a place where a
// caller-supplied target or source IP is written unchecked.
type EventError struct {
	Field  string
	Reason string
}

func (e *EventError) Error() string {
	return fmt.Sprintf("%s: field %s %s", ErrInvalidEvent.Error(), e.Field, e.Reason)
}

func (e *EventError) Unwrap() error { return ErrInvalidEvent }

func invalid(field, reason string) error { return &EventError{Field: field, Reason: reason} }

// Appender is the production implementation of the Writer interface in event.go.
//
// It is deliberately the only place that knows the audit_events and audit_heads SQL.
// The verifier has its own read queries and never shares a write path with it, so a
// bug in verification cannot damage the chain and a bug in appending cannot hide
// itself from verification.
type Appender struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// The Appender must satisfy the frozen cross-slice interface. This assertion is the
// compile-time check that it does.
var _ Writer = (*Appender)(nil)

// NewAppender returns the audit writer over db. It returns an error rather than a
// half-wired Appender when db is nil: an audit writer that silently discards events
// is exactly the failure mode this slice exists to prevent, and it would look healthy
// from every other slice's point of view.
func NewAppender(db *store.DB) (*Appender, error) {
	if db == nil {
		return nil, ErrNoDatabase
	}
	pool := db.Pool()
	if pool == nil {
		return nil, ErrNoDatabase
	}
	return &Appender{pool: pool, log: slog.Default()}, nil
}

// WithLogger returns a copy of a that logs to log. A nil log is ignored, so a caller
// can pass one unconditionally.
func (a *Appender) WithLogger(log *slog.Logger) *Appender {
	if a == nil || log == nil {
		return a
	}
	clone := *a
	clone.log = log
	return &clone
}

func (a *Appender) logger() *slog.Logger {
	if a == nil || a.log == nil {
		return slog.Default()
	}
	return a.log
}

// Append records e in its own transaction. It is used for events that are not part of
// a business change — logins, logouts and denials — where there is no other write for
// the event to be atomic with.
func (a *Appender) Append(ctx context.Context, e Event) (Event, error) {
	if a == nil || a.pool == nil {
		return Event{}, ErrNoDatabase
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var out Event
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		stored, err := a.appendTx(ctx, tx, e)
		if err != nil {
			return err
		}
		out = stored
		return nil
	})
	if err != nil {
		return Event{}, err
	}
	return out, nil
}

// AppendTx records e in the caller's transaction, so a business change and the record
// of it commit or roll back together.
//
// The caller's transaction is used as-is: this function never commits or rolls back.
// It does take the chain's head lock, which is held until the caller commits, so a
// long-running business transaction delays other appends to the same chain. That is
// the intended trade: the alternative is an audit row that can commit without its
// change, or a change that commits without its audit row.
func (a *Appender) AppendTx(ctx context.Context, tx pgx.Tx, e Event) (Event, error) {
	if a == nil {
		return Event{}, ErrNoDatabase
	}
	if tx == nil {
		return Event{}, invalid("tx", "is nil; AppendTx needs the caller's transaction, use Append otherwise")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return a.appendTx(ctx, tx, e)
}

// appendTx is the single implementation of an append. Both entry points funnel here,
// so there is one ordering of the four statements and no second copy to drift.
func (a *Appender) appendTx(ctx context.Context, tx pgx.Tx, e Event) (Event, error) {
	event, timestampDefaulted, err := prepare(e)
	if err != nil {
		return Event{}, err
	}
	if timestampDefaulted {
		// Visible tolerance, not silent tolerance: the event is accurate, but the
		// caller still has a bug. Naming the action and target is what makes it
		// findable; neither is a secret value.
		a.logger().Warn("audit: the caller did not set an event timestamp; the append time was used",
			"event", "audit_timestamp_defaulted",
			"action", event.Action,
			"target", event.Target,
			"scope", event.Scope,
			"actor_id", event.ActorID,
		)
	}

	// A lock timeout rather than a statement timeout: the append should wait briefly
	// for its own chain, never forever, and the caller's context still bounds the
	// whole request. SET LOCAL is scoped to this transaction, so it cannot leak onto
	// a pooled connection.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", LockTimeout.Milliseconds())); err != nil {
		return Event{}, fmt.Errorf("audit: could not set the append lock timeout: %w", err)
	}

	// 1. Ensure the head row exists. On a scope's first event there is nothing to
	//    lock yet, so the row is created at seq 0 / hash '' and the SELECT below then
	//    always finds something to lock.
	//
	//    ON CONFLICT DO NOTHING is what makes this race-safe: two concurrent first
	//    appends both try the insert, one creates the row, the other waits for that
	//    insert to commit and then does nothing. Neither errors, and the SELECT FOR
	//    UPDATE that follows serialises them.
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_heads (scope, seq, hash) VALUES ($1, 0, '')
		 ON CONFLICT (scope) DO NOTHING`,
		event.Scope,
	); err != nil {
		return Event{}, fmt.Errorf("audit: could not ensure the head row: %w", err)
	}

	// 2. Lock the chain and read its tail. This is the serialisation point for the
	//    scope: every append to this chain holds this row lock until it commits.
	var headSeq int64
	var headHash string
	if err := tx.QueryRow(ctx,
		`SELECT seq, hash FROM audit_heads WHERE scope = $1 FOR UPDATE`,
		event.Scope,
	).Scan(&headSeq, &headHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The INSERT above guarantees a row, so this means the head was deleted
			// by something else between the two statements. Refusing is the only
			// safe answer: continuing would restart the chain at seq 1 over rows
			// that already exist and collide on the primary key.
			return Event{}, fmt.Errorf("audit: the head row for this scope vanished during the append: %w", err)
		}
		return Event{}, fmt.Errorf("audit: could not lock the head row: %w", err)
	}

	// 3. Compute the link. seq and hash are never taken from the caller: seq is the
	//    locked head plus one, and the hash is computed here from the frozen encoding.
	//
	//    The head row of a scope is created at seq 0 with an empty hash, because there
	//    is no previous event to describe. That empty hash is a sentinel meaning "this
	//    chain has no events yet", NOT a link value: the first event of a scope links to
	//    GenesisHash (32 zero bytes, docs/CONTRACTS.md §7). Using the sentinel as the
	//    link would make the first row's prev_hash the empty string, and the verifier —
	//    which fixes the expected first link at GenesisHash — would report a
	//    prev_hash_mismatch on every healthy chain.
	prevHash := headHash
	if headSeq == 0 {
		prevHash = GenesisHash
	}
	event.Seq = headSeq + 1
	event.PrevHash = prevHash
	hash := HashFor(event, prevHash)

	// 4. Insert the event. The (scope, seq) primary key makes a duplicate impossible,
	//    so a second writer that somehow computed the same seq fails here instead of
	//    forking the chain.
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events
		   (scope, seq, ts, actor_id, actor_kind, org_id, action, target, source_ip, result, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		event.Scope, event.Seq, event.Timestamp, event.ActorID, string(event.ActorKind),
		event.OrgID, event.Action, event.Target, event.SourceIP, string(event.Result),
		event.PrevHash, hash,
	); err != nil {
		return Event{}, fmt.Errorf("audit: could not insert the event: %w", err)
	}

	// 5. Advance the head, in the same transaction. A zero-row update would mean the
	//    head moved under us despite the lock, which must never be silently accepted:
	//    the events would then be ahead of the head and verification would report a
	//    tamper on a healthy database.
	tag, err := tx.Exec(ctx,
		`UPDATE audit_heads SET seq = $2, hash = $3 WHERE scope = $1`,
		event.Scope, event.Seq, hash,
	)
	if err != nil {
		return Event{}, fmt.Errorf("audit: could not advance the head row: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Event{}, fmt.Errorf("audit: advancing the head row updated %d rows, expected 1", tag.RowsAffected())
	}

	return event, nil
}

// inTx runs fn in a transaction and commits it, or rolls it back on error or panic.
// It is a small local copy of store.Base.InTx because the Appender holds a pool
// directly and the rollback must happen on a fresh context: the request context may
// already be cancelled when the append fails, and a rollback that does not run holds
// the chain's head lock until the connection is recycled.
func (a *Appender) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: could not begin the append transaction: %w", err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			a.logger().Warn("audit: could not roll back an append", "error", err.Error())
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: could not commit the append transaction: %w", err)
	}
	committed = true
	return nil
}

// prepare validates e and returns the event as it will be stored: timestamps
// truncated to the chain's precision, sequence and link left for appendTx to assign.
//
// Validation is deliberately strict about the fields that are part of the hash. An
// event with an empty scope, an invented action name or an unknown result is a
// caller bug, and storing it would put a row in the log that no reader can interpret
// and that every verifier would then faithfully include in the chain. Failing the
// append is the only way to keep the log meaningful.
//
// The rule for what may be defaulted rather than rejected has three parts, and a
// field must pass all of them:
//
//  1. the writer legitimately owns the field, so the caller is not being overruled
//     about something that is theirs to decide;
//  2. the omission cannot forge anything — it grants no privilege and hides no
//     action;
//  3. the writer knows the true value better than the caller does.
//
// Timestamp is the only field that passes. seq, prev_hash and hash are computed from
// the locked head (a caller-supplied one is a fork attempt). Scope decides which
// tenant's chain the row lands on. Action, result and actor_kind are the row's
// meaning: a defaulted one would be invented data in an append-only log. NUL bytes
// cannot be stored at all. Those are all rejected.
//
// A zero Timestamp is an omission, not a lie: it grants nothing, hides nothing, and
// the append's own clock is the better answer. Rejecting it would be fail-closed in
// the wrong place — because this runs inside the caller's transaction, a hard
// rejection rolls back the caller's whole business change, so one peer forgetting the
// field would take secret writes down entirely. The omission is still made visible
// with a WARN naming the action and target, so the defect is findable rather than
// silently tolerated.
func prepare(e Event) (Event, bool, error) {
	timestampDefaulted := false

	if strings.TrimSpace(e.Scope) == "" {
		// Never default to PlatformScope. An organization's event silently landing
		// on the platform chain would be a cross-tenant leak into the log that the
		// platform admin can read.
		return Event{}, false, invalid("scope", "is empty; an event must name its chain (an organization id or PlatformScope)")
	}
	if e.Seq != 0 {
		// A caller-supplied sequence is how a chain gets forked. seq is assigned from
		// the locked head and nothing else.
		return Event{}, false, invalid("seq", "was set by the caller; the sequence is assigned by the append")
	}
	if !IsKnownAction(e.Action) {
		return Event{}, false, invalid("action", "is not a frozen action name (docs/CONTRACTS.md §3)")
	}
	switch e.Result {
	case ResultSuccess, ResultDenied, ResultFailed:
	default:
		return Event{}, false, invalid("result", "must be success, denied or failed")
	}
	switch e.ActorKind {
	case ActorUser, ActorService, ActorPlatform, ActorAnonymous:
	default:
		// The kind is part of the hash, so an empty or unknown one is not a cosmetic
		// problem: it is an event that cannot be attributed and cannot be fixed
		// afterwards, because the log is append-only.
		return Event{}, false, invalid("actor_kind", "must be user, service, platform or anonymous")
	}
	if e.Timestamp.IsZero() {
		// Defaulted, not rejected — see the rule above. time.Now().UTC() is truncated
		// to the microsecond by TruncateTimestamp below, which is the precision
		// timestamptz stores; a nanosecond value would hash differently at write time
		// than at verify time and report a false tamper on a healthy chain.
		//
		// The caller is told, in the log, so the omission is fixed at its source. The
		// fields named here are the action and the target: neither is a secret value,
		// and the target is what lets someone find the call site.
		e.Timestamp = time.Now()
		timestampDefaulted = true
	}
	if e.PrevHash != "" {
		// The link is computed from the locked head. A caller that supplies one has
		// misunderstood the contract, and honouring it would let a caller pick its
		// own predecessor.
		if !isHexHash(e.PrevHash) {
			return Event{}, false, invalid("prev_hash", "must be empty or 64 lowercase hex characters; the link is computed by the append")
		}
		return Event{}, false, invalid("prev_hash", "was set by the caller; the link is computed by the append")
	}
	for _, field := range []struct{ name, value string }{
		{"actor_id", e.ActorID},
		{"org_id", e.OrgID},
		{"target", e.Target},
		{"source_ip", e.SourceIP},
		{"scope", e.Scope},
	} {
		// NUL cannot be stored in a PostgreSQL text column, so it would surface as a
		// driver error rather than a validation error. Nothing else is rejected here:
		// the log is read as JSON, so a newline in a target is escaped rather than
		// becoming an injection.
		if strings.ContainsRune(field.value, 0) {
			return Event{}, false, invalid(field.name, "contains a NUL byte")
		}
	}

	e.Timestamp = TruncateTimestamp(e.Timestamp)
	e.PrevHash = ""
	e.Seq = 0
	return e, timestampDefaulted, nil
}

// isHexHash reports whether s is 64 lowercase hex characters, the shape of every hash
// this package writes.
func isHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
