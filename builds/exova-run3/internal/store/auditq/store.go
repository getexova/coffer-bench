// Package auditq is the read side of the audit log: filtered reads and the chain
// scan that verification walks.
//
// Rules that hold for every query in this package:
//   - Reads are scoped by chain scope, which is an organization ID or
//     audit.PlatformScope. A read never crosses scopes, and the scope is always a
//     bound parameter taken from the caller's own actor, never from a request field.
//   - Verification walks audit_events from seq 1 per scope and rebuilds the canonical
//     bytes from the row's own columns; it never trusts audit_heads
//     (docs/CONTRACTS.md §7). A head/events disagreement is its own finding.
//   - The audit log is append-only and the runtime role cannot UPDATE or DELETE it,
//     so this package has no write path at all. Every statement here is a SELECT.
//
// This package returns the frozen field set and nothing else. There is deliberately
// no column here that could carry a secret value: the log never stores one, so no
// reader can leak one.
package auditq

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/audit"
	"coffer/internal/store"
)

// Limits for a filtered read (SPEC §7.2 `GET /audit?limit=`).
const (
	// DefaultLimit is how many events a read returns when the caller does not say.
	DefaultLimit = 100
	// MaxLimit caps a read, so one request cannot ask for an unbounded page.
	MaxLimit = 1000
)

// ErrNoDatabase is returned when the store has no pool.
var ErrNoDatabase = errors.New("auditq: no database")

// Store is the audit read model. It implements audit.EventScanner, which is the
// narrow interface the verifier depends on, so the verifier can be tested against an
// in-memory chain without a database.
//
// It holds the pool rather than a store.Base because every statement it issues is a
// SELECT against the two audit tables: it needs nothing else the base carries, and a
// read model that cannot reach the rest of the schema is one less way for the audit
// read path to be bent into a cross-tenant query.
type Store struct {
	pool *pgxpool.Pool
}

// The read model must satisfy the verifier's scanner interface.
var _ audit.EventScanner = (*Store)(nil)

// New returns the audit read model over the database the composition root provides.
func New(db *store.DB) *Store {
	if db == nil {
		return &Store{}
	}
	return &Store{pool: db.Pool()}
}

// NewFromPool returns the read model over an existing pool. Tests use it when they
// already hold a pool; production uses New.
func NewFromPool(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) poolOrNil() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.pool
}

// Filter is a filtered read of one chain.
type Filter struct {
	// Scope is the chain to read: an organization ID or audit.PlatformScope.
	Scope string
	// Actor is the actor id to match exactly, or "" for every actor.
	Actor string
	// Action is a frozen action name to match exactly, or "" for every action.
	Action string
	// Since keeps events at or after this instant. The zero value means no bound.
	Since time.Time
	// Limit is the maximum number of events to return. Zero means DefaultLimit;
	// anything above MaxLimit is clamped to MaxLimit.
	Limit int
}

// Event is one audit event as the API returns it: the frozen field set from SPEC §4.
//
// The field set is exactly seq, timestamp, actor, action, target, source_ip, result,
// prev_hash and hash. It carries no organization, no actor kind and no scope, because
// a caller has already been confined to one chain and those fields would only restate
// that. It carries no value and nothing derived from a value.
type Event struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	SourceIP  string `json:"source_ip"`
	Result    string `json:"result"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// List returns one page of the chain, newest first.
//
// Newest first is deliberate: `limit` on an audit log almost always means "the most
// recent N", and returning the OLDEST N when an operator asks for the last 100 events
// would hide exactly the events they are investigating. A caller that wants
// chronological order reverses the slice, which is cheap because the page is bounded.
func (s *Store) List(ctx context.Context, f Filter) ([]Event, error) {
	pool := s.poolOrNil()
	if pool == nil {
		return nil, ErrNoDatabase
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if f.Scope == "" {
		return nil, errors.New("auditq: a read needs a scope")
	}

	limit := clampLimit(f.Limit)

	// The filters are applied as SQL predicates on bound parameters rather than by
	// building a WHERE clause from strings, so a filter value can never become SQL.
	// `$4::timestamptz IS NULL` is how "no since bound" is expressed without a second
	// query: a NULL argument disables the predicate.
	var since any
	if !f.Since.IsZero() {
		since = f.Since.UTC()
	}

	rows, err := pool.Query(ctx, `
		SELECT seq, ts, actor_id, action, target, source_ip, result, prev_hash, hash
		  FROM audit_events
		 WHERE scope = $1
		   AND ($2 = '' OR actor_id = $2)
		   AND ($3 = '' OR action = $3)
		   AND ($4::timestamptz IS NULL OR ts >= $4::timestamptz)
		 ORDER BY seq DESC
		 LIMIT $5`,
		f.Scope, f.Actor, f.Action, since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("auditq: could not read the audit log: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0, min(limit, 64))
	for rows.Next() {
		var (
			e  Event
			ts time.Time
		)
		if err := rows.Scan(&e.Seq, &ts, &e.Actor, &e.Action, &e.Target, &e.SourceIP,
			&e.Result, &e.PrevHash, &e.Hash); err != nil {
			return nil, fmt.Errorf("auditq: could not read an audit event: %w", err)
		}
		// Render the timestamp in the canonical form, so what the log shows is
		// byte-for-byte the value that was hashed. An operator can then recompute a
		// row's hash by hand from what the API printed.
		e.Timestamp = audit.FormatTimestamp(ts)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditq: could not read the audit log: %w", err)
	}
	return events, nil
}

// Count returns how many events a scope holds. The API does not use it; it exists for
// an operator check and for tests that need to assert on chain length.
func (s *Store) Count(ctx context.Context, scope string) (int64, error) {
	pool := s.poolOrNil()
	if pool == nil {
		return 0, ErrNoDatabase
	}
	if scope == "" {
		return 0, errors.New("auditq: a count needs a scope")
	}
	var n int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE scope = $1`, scope,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("auditq: could not count the audit log: %w", err)
	}
	return n, nil
}

// ScanScope returns up to limit events with seq > afterSeq, in ascending sequence
// order. It is the verifier's read (audit.EventScanner).
//
// It reads every column the canonical encoding covers, because the verifier rebuilds
// the hash from them. It does not read audit_heads: that is a separate call, so the
// events and the head are two independent observations rather than one joined view
// that could hide a disagreement.
//
// Rows are ordered by seq ascending and nothing else. The verifier's gap detection
// depends on seeing every row that exists, in order, so this query must never skip
// one — which is also why it does not filter on anything but the scope.
func (s *Store) ScanScope(ctx context.Context, scope string, afterSeq int64, limit int) ([]audit.StoredEvent, error) {
	pool := s.poolOrNil()
	if pool == nil {
		return nil, ErrNoDatabase
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if scope == "" {
		return nil, errors.New("auditq: a scan needs a scope")
	}
	if limit <= 0 {
		limit = 500
	}

	rows, err := pool.Query(ctx, `
		SELECT scope, seq, ts, actor_id, actor_kind, org_id, action, target, source_ip,
		       result, prev_hash, hash
		  FROM audit_events
		 WHERE scope = $1 AND seq > $2
		 ORDER BY seq ASC
		 LIMIT $3`,
		scope, afterSeq, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("auditq: could not scan the audit chain: %w", err)
	}
	defer rows.Close()

	out := make([]audit.StoredEvent, 0, min(limit, 64))
	for rows.Next() {
		var (
			row  audit.StoredEvent
			ts   time.Time
			kind string
			res  string
		)
		// The scope column is read and used, even though the query already filtered on
		// it: the canonical encoding covers scope, so a rebuild that left it empty would
		// hash different bytes from the ones the writer hashed, and every row would
		// report a hash mismatch on a healthy chain.
		if err := rows.Scan(
			&row.Scope, &row.Seq, &ts, &row.ActorID, &kind, &row.OrgID, &row.Action, &row.Target,
			&row.SourceIP, &res, &row.PrevHash, &row.Hash,
		); err != nil {
			return nil, fmt.Errorf("auditq: could not read an audit event: %w", err)
		}
		// The timestamp must be the exact instant the row holds. audit.FormatTimestamp
		// truncates to the microsecond, which is the precision timestamptz stores, so
		// the canonical bytes rebuilt here are identical to the ones hashed at append
		// time. Rendering it any other way would make every verification fail.
		row.Timestamp = ts.UTC().Truncate(time.Microsecond)
		row.ActorKind = audit.ActorKind(kind)
		row.Result = audit.Result(res)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditq: could not scan the audit chain: %w", err)
	}
	return out, nil
}

// Head returns the scope's audit_heads row, with Present false when there is none
// (audit.EventScanner).
//
// A missing head is not an error: it is the normal state of a scope that has never
// had an event, and the verifier decides what it means from whether any events exist.
func (s *Store) Head(ctx context.Context, scope string) (audit.Head, error) {
	pool := s.poolOrNil()
	if pool == nil {
		return audit.Head{}, ErrNoDatabase
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if scope == "" {
		return audit.Head{}, errors.New("auditq: a head read needs a scope")
	}

	var head audit.Head
	err := pool.QueryRow(ctx,
		`SELECT seq, hash FROM audit_heads WHERE scope = $1`, scope,
	).Scan(&head.Seq, &head.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return audit.Head{Present: false}, nil
	}
	if err != nil {
		return audit.Head{}, fmt.Errorf("auditq: could not read the audit head: %w", err)
	}
	head.Present = true
	return head, nil
}

// Scopes lists every chain scope that holds events, for an operator check and for
// tests. It never crosses a tenant boundary in the API: no route exposes it, and the
// platform admin's view is the platform chain alone.
func (s *Store) Scopes(ctx context.Context) ([]string, error) {
	pool := s.poolOrNil()
	if pool == nil {
		return nil, ErrNoDatabase
	}
	rows, err := pool.Query(ctx, `SELECT DISTINCT scope FROM audit_events ORDER BY scope`)
	if err != nil {
		return nil, fmt.Errorf("auditq: could not list the audit scopes: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("auditq: could not list the audit scopes: %w", err)
		}
		out = append(out, scope)
	}
	return out, rows.Err()
}

// clampLimit applies the default and the cap to a requested page size.
func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultLimit
	case limit > MaxLimit:
		return MaxLimit
	default:
		return limit
	}
}
