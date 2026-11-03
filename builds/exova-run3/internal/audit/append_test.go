package audit_test

// Database-backed tests for the append path and the verifier.
//
// These are the tests that cannot be faked: a real PostgreSQL, the real schema and
// triggers from 0001_init.sql, real transactions, and a superuser connection to do the
// tampering that the runtime role is forbidden to do.
//
// They skip cleanly when COFFER_TEST_DATABASE_URL is unset, so `go test ./...` stays
// green on a machine with no database, and they are the only place a claim about the
// chain's behaviour under a real database is made.
//
// The tamper probes deliberately use the OWNER (superuser) connection, because the
// append-only trigger refuses UPDATE and DELETE for every other role — that refusal is
// itself asserted, in TestRuntimeRoleCannotTamper.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/store"
	"coffer/internal/store/auditq"
)

// testDSN is the owner (superuser) URL the tests use to create the schema and to
// tamper. It is the same variable internal/testutil uses.
const testDSNEnv = "COFFER_TEST_DATABASE_URL"

// testAppDSNEnv is the optional coffer_app URL. When it is set together with
// COFFER_APP_DB_PASSWORD, the runtime pool runs as the unprivileged role and the
// append-only trigger is exercised for real.
const testAppDSNEnv = "COFFER_TEST_APP_DATABASE_URL"

// dbHarness is one migrated database with an Appender and a read model over it.
type dbHarness struct {
	db       *store.DB
	appender *audit.Appender
	reader   *auditq.Store
	owner    *pgx.Conn
	scope    string
	logs     *logBuffer
}

// logBuffer collects server log output so a test can assert that a tolerated defect is
// still visible rather than silently swallowed.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// newDBHarness boots the schema and returns the harness, or skips when no database is
// configured.
func newDBHarness(t *testing.T) *dbHarness {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(testDSNEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping the database-backed audit test (set it to a postgres URL to run)", testDSNEnv)
	}

	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	values := map[string]string{
		"COFFER_MASTER_KEY":               "0J4n1s0XQ2m8bV3kR7pY6tL9wZ2cF5hD8gK1nM4qS0U=",
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "platform-admin@audit-test.invalid",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "audit-test-bootstrap-password",
		"COFFER_ENV":                      config.EnvDevelopment,
		"COFFER_MIGRATION_DATABASE_URL":   dsn,
		"DATABASE_URL":                    dsn,
		"COFFER_ALLOW_DEGRADED_DB_ROLE":   "1",
	}

	// When an app-role URL is supplied, the runtime pool runs as coffer_app and the
	// append-only trigger is actually exercised. Without it the pool is the owner role,
	// which the schema deliberately permits to tamper so that restore.sh can reproduce
	// a tampered dump — so TestRuntimeRoleCannotTamper skips rather than asserting
	// something the schema does not promise.
	if appDSN := strings.TrimSpace(os.Getenv(testAppDSNEnv)); appDSN != "" {
		if appPassword := strings.TrimSpace(os.Getenv("COFFER_APP_DB_PASSWORD")); appPassword != "" {
			values["DATABASE_URL"] = appDSN
			values["COFFER_APP_DB_PASSWORD"] = appPassword
			delete(values, "COFFER_ALLOW_DEGRADED_DB_ROLE")
		}
	}
	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	})
	if err != nil {
		t.Fatalf("test configuration is invalid: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	db, err := store.Boot(ctx, cfg, log)
	if err != nil {
		t.Fatalf("could not boot the test database: %v", err)
	}
	t.Cleanup(db.Close)

	appender, err := audit.NewAppender(db)
	if err != nil {
		t.Fatalf("could not build the appender: %v", err)
	}
	// The appender must log through the captured handler, not the process default.
	appender = appender.WithLogger(log)

	// The owner connection, used only for tampering and for setup the runtime role may
	// not do. It is the same URL the migrations used.
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("could not open the owner connection: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = owner.Close(closeCtx)
	})

	return &dbHarness{
		db:       db,
		appender: appender,
		reader:   auditq.New(db),
		owner:    owner,
		logs:     logs,
		// A fresh scope per test, so tests never see each other's chains and can run in
		// any order.
		scope: fmt.Sprintf("org_e3_%d_%s", os.Getpid(), randomScopeSuffix()),
	}
}

func randomScopeSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// mustAppend appends one event and fails the test on error.
func (h *dbHarness) mustAppend(t *testing.T, target string) audit.Event {
	t.Helper()
	ev, err := h.appender.Append(context.Background(), audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretRead,
		Target:    target,
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	return ev
}

// verify runs the real verifier over the real database.
func (h *dbHarness) verify(t *testing.T) audit.Verdict {
	t.Helper()
	v, err := audit.Verify(context.Background(), h.reader, h.scope)
	if err != nil {
		t.Fatalf("Verify returned an error: %v", err)
	}
	return v
}

// TestAppendStartsChainAtGenesis: the first event of a scope is seq 1 and links to the
// genesis hash, and the head row is created by the append itself.
func TestAppendStartsChainAtGenesis(t *testing.T) {
	h := newDBHarness(t)

	first := h.mustAppend(t, "project/p/env/e/key/FIRST")

	if first.Seq != 1 {
		t.Fatalf("the first event of a scope must be seq 1, got %d", first.Seq)
	}
	if first.PrevHash != audit.GenesisHash {
		t.Fatalf("the first event must link to the genesis hash, got %q", first.PrevHash)
	}
	// The returned hash must be the one the row's own columns imply.
	stored, err := h.reader.ScanScope(context.Background(), h.scope, 0, 10)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored event, got %d", len(stored))
	}
	if got := stored[0].ComputeHash(); got != stored[0].Hash {
		t.Fatalf("the stored hash is not the hash the row's columns imply\n stored: %s\n   impl: %s", stored[0].Hash, got)
	}
	if v := h.verify(t); !v.Valid {
		t.Fatalf("a freshly appended chain did not verify: %s", v.Describe())
	}
}

// TestAppendRoundTripsBytes is the timestamp round-trip proof: the canonical bytes
// rebuilt from the database row are identical to the bytes hashed at append time.
// A precision mismatch here would make every verification fail.
func TestAppendRoundTripsBytes(t *testing.T) {
	h := newDBHarness(t)

	// A timestamp with sub-microsecond digits, which is what time.Now() produces. The
	// writer must truncate it before hashing, or the row would come back rounded by
	// PostgreSQL and hash differently.
	appended := h.mustAppend(t, "project/p/env/e/key/ROUNDTRIP")

	stored, err := h.reader.ScanScope(context.Background(), h.scope, 0, 10)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored event, got %d", len(stored))
	}

	if !stored[0].Timestamp.Equal(appended.Timestamp) {
		t.Fatalf("the timestamp did not round-trip\n appended: %s\n   stored: %s",
			appended.Timestamp.Format(time.RFC3339Nano), stored[0].Timestamp.Format(time.RFC3339Nano))
	}
	if got, want := string(stored[0].Canonical()), string(audit.Canonical(appended, appended.PrevHash)); got != want {
		t.Fatalf("the canonical bytes did not round-trip through the database\n stored: %s\nappend: %s", got, want)
	}
	// audit.Event deliberately has no hash field, so the expected hash is the one the
	// event's own columns and link imply — the same value the writer stored.
	wantHash := audit.HashFor(appended, appended.PrevHash)
	if got := stored[0].ComputeHash(); got != wantHash {
		t.Fatalf("the hash recomputed from the row is not the hash of the appended event\n  row: %s\n want: %s", got, wantHash)
	}
	if stored[0].Hash != wantHash {
		t.Fatalf("the stored hash is not the hash of the appended event\nstored: %s\n  want: %s", stored[0].Hash, wantHash)
	}
	if v := h.verify(t); !v.Valid {
		t.Fatalf("the chain did not verify after a round trip: %s", v.Describe())
	}
}

// TestAppendIsGapless: successive appends produce 1..n with each row linking to the
// previous one.
func TestAppendIsGapless(t *testing.T) {
	h := newDBHarness(t)

	const n = 10
	prev := audit.GenesisHash
	for i := 1; i <= n; i++ {
		ev := h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
		if ev.Seq != int64(i) {
			t.Fatalf("append %d got seq %d, expected %d", i, ev.Seq, i)
		}
		if ev.PrevHash != prev {
			t.Fatalf("append %d prev_hash is not the previous hash", i)
		}
		prev = audit.HashFor(ev, ev.PrevHash)
	}

	if v := h.verify(t); !v.Valid || v.Events != n {
		t.Fatalf("expected a valid chain of %d events, got %s", n, v.Describe())
	}
}

// TestConcurrentAppendsAreGapless is the concurrency invariant: two appends to one
// scope serialise on the head row, so the chain has no duplicate and no missing
// sequence. A lost update here would be a permanently forked chain.
func TestConcurrentAppendsAreGapless(t *testing.T) {
	h := newDBHarness(t)

	const workers = 8
	const perWorker = 5
	const total = workers * perWorker

	var wg sync.WaitGroup
	errs := make(chan error, total)
	seqs := make(chan int64, total)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				ev, err := h.appender.Append(context.Background(), audit.Event{
					Scope:     h.scope,
					Timestamp: time.Now().UTC(),
					ActorID:   fmt.Sprintf("user_w%d", worker),
					ActorKind: audit.ActorUser,
					OrgID:     h.scope,
					Action:    audit.ActionSecretWrite,
					Target:    fmt.Sprintf("project/p/env/e/key/W%d_%d", worker, i),
					SourceIP:  "203.0.113.7",
					Result:    audit.ResultSuccess,
				})
				if err != nil {
					errs <- err
					return
				}
				seqs <- ev.Seq
			}
		}(w)
	}

	wg.Wait()
	close(errs)
	close(seqs)

	for err := range errs {
		t.Fatalf("a concurrent append failed: %v", err)
	}

	// Every sequence from 1 to total must appear exactly once.
	seen := make(map[int64]int, total)
	for seq := range seqs {
		seen[seq]++
	}
	if len(seen) != total {
		t.Fatalf("expected %d distinct sequence numbers, got %d", total, len(seen))
	}
	for seq := 1; seq <= total; seq++ {
		if seen[int64(seq)] != 1 {
			t.Fatalf("seq %d appeared %d times, expected exactly once", seq, seen[int64(seq)])
		}
	}

	// And the chain must verify, which proves every prev_hash link is intact after the
	// interleaving.
	v := h.verify(t)
	if !v.Valid {
		t.Fatalf("the concurrently built chain did not verify: %s", v.Describe())
	}
	if v.Events != total {
		t.Fatalf("expected %d events, got %d", total, v.Events)
	}
}

// TestAppendTxJoinsCallerTransaction: an AppendTx that the caller rolls back leaves no
// event and no head advance. This is what makes a business change and its audit row
// commit together.
func TestAppendTxJoinsCallerTransaction(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("could not begin: %v", err)
	}
	if _, err := h.appender.AppendTx(ctx, tx, audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretWrite,
		Target:    "project/p/env/e/key/ROLLED_BACK",
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("AppendTx failed: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	count, err := h.reader.Count(ctx, h.scope)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("a rolled-back AppendTx left %d events; the append is not in the caller's transaction", count)
	}
	head, err := h.reader.Head(ctx, h.scope)
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}
	if head.Present && head.Seq != 0 {
		t.Fatalf("a rolled-back AppendTx advanced the head to seq %d", head.Seq)
	}
}

// TestAppendTxCommitsWithCaller: when the caller commits, the event and the head are
// both there.
func TestAppendTxCommitsWithCaller(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("could not begin: %v", err)
	}
	if _, err := h.appender.AppendTx(ctx, tx, audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretWrite,
		Target:    "project/p/env/e/key/COMMITTED",
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("AppendTx failed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	if v := h.verify(t); !v.Valid || v.Events != 1 {
		t.Fatalf("expected a valid chain of 1 event after commit, got %s", v.Describe())
	}
}

// TestAppendRejectsCallerSuppliedSeqAndHash: the writer never trusts a caller's seq or
// link, because that is how a chain is forked.
func TestAppendRejectsCallerSuppliedSeqAndHash(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	base := audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretRead,
		Target:    "project/p/env/e/key/X",
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	}

	withSeq := base
	withSeq.Seq = 99
	if _, err := h.appender.Append(ctx, withSeq); err == nil {
		t.Fatal("Append accepted a caller-supplied seq")
	}

	withPrev := base
	withPrev.PrevHash = strings.Repeat("a", 64)
	if _, err := h.appender.Append(ctx, withPrev); err == nil {
		t.Fatal("Append accepted a caller-supplied prev_hash")
	}

	if count, _ := h.reader.Count(ctx, h.scope); count != 0 {
		t.Fatalf("a rejected append still wrote %d events", count)
	}
}

// TestAppendRejectsInvalidEvents: an event that cannot be interpreted must not enter
// an append-only log, because it can never be corrected.
func TestAppendRejectsInvalidEvents(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	valid := audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretRead,
		Target:    "t",
		Result:    audit.ResultSuccess,
	}

	cases := []struct {
		name  string
		event audit.Event
	}{
		{"empty_scope", func() audit.Event { e := valid; e.Scope = ""; return e }()},
		{"unknown_action", func() audit.Event { e := valid; e.Action = "secret.exfiltrate"; return e }()},
		{"unknown_result", func() audit.Event { e := valid; e.Result = "maybe"; return e }()},
		{"unknown_actor_kind", func() audit.Event { e := valid; e.ActorKind = "robot"; return e }()},
		{"nul_in_target", func() audit.Event { e := valid; e.Target = "a\x00b"; return e }()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.appender.Append(ctx, tc.event); err == nil {
				t.Fatalf("Append accepted an invalid event (%s)", tc.name)
			}
		})
	}
	if count, _ := h.reader.Count(ctx, h.scope); count != 0 {
		t.Fatalf("invalid events wrote %d rows", count)
	}
}

// TestZeroTimestampIsDefaultedNotRejected pins the deliberate asymmetry: an omitted
// timestamp is an omission the writer can fix, so the append succeeds with the append
// time and logs a WARN. Everything else in an event is still rejected.
//
// The reason this is not a rejection: prepare runs inside the caller's transaction, so
// a hard rejection rolls back the caller's whole business change. One peer forgetting
// the field would take secret writes down entirely — a product outage for a field the
// writer legitimately owns.
func TestZeroTimestampIsDefaultedNotRejected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	before := time.Now().UTC()
	stored, err := h.appender.Append(ctx, audit.Event{
		Scope:     h.scope,
		Timestamp: time.Time{}, // omitted on purpose
		ActorID:   "user_e3",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretWrite,
		Target:    "project/p/env/e/key/NO_TIMESTAMP",
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	})
	if err != nil {
		t.Fatalf("an omitted timestamp must be defaulted, not rejected: %v", err)
	}
	after := time.Now().UTC()

	if stored.Timestamp.Before(before.Truncate(time.Microsecond)) || stored.Timestamp.After(after) {
		t.Fatalf("the defaulted timestamp %s is not the append time (between %s and %s)",
			stored.Timestamp, before, after)
	}

	// Microsecond precision, or the row would hash differently when read back.
	rows, err := h.reader.ScanScope(ctx, h.scope, 0, 10)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if got := rows[0].Timestamp.UTC().Format(audit.TimestampLayout); got != audit.FormatTimestamp(stored.Timestamp) {
		t.Fatalf("the stored timestamp is not the canonical microsecond form: %q", got)
	}
	// And the row is internally consistent, so the chain still verifies.
	if got := rows[0].ComputeHash(); got != rows[0].Hash {
		t.Fatalf("a defaulted timestamp produced an inconsistent row\n rebuilt: %s\n  stored: %s", got, rows[0].Hash)
	}
	if v := h.verify(t); !v.Valid {
		t.Fatalf("a defaulted timestamp broke the chain: %s", v.Describe())
	}

	// Tolerated, but visibly: the WARN names the action and the target so the caller's
	// omission can be found and fixed at its source.
	logged := h.logs.String()
	for _, want := range []string{
		"event=audit_timestamp_defaulted",
		"action=secret.write",
		"target=project/p/env/e/key/NO_TIMESTAMP",
		"level=WARN",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("the defaulted-timestamp warning is missing %q; log was:\n%s", want, logged)
		}
	}
}

// --- the tamper probes ---------------------------------------------------------

// TestSuperuserTargetTamperIsDetected is THE probe: a superuser edits one row's
// target, and verification must report that exact sequence.
//
// The runtime role cannot do this — the append-only trigger refuses it — so the edit
// is made over the owner connection, which is what an attacker with database
// credentials or a restored tampered dump would have.
func TestSuperuserTargetTamperIsDetected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}
	if v := h.verify(t); !v.Valid {
		t.Fatalf("the chain did not verify before tampering: %s", v.Describe())
	}

	// The tamper: seq 2's target, changed to 'x'. The hash column is left alone, which
	// is the realistic case — an attacker editing a row through psql does not recompute
	// a SHA-256 chain.
	if _, err := h.owner.Exec(ctx,
		`UPDATE audit_events SET target = 'x' WHERE scope = $1 AND seq = 2`, h.scope,
	); err != nil {
		t.Fatalf("the superuser tamper did not apply: %v", err)
	}

	v := h.verify(t)
	if v.Valid {
		t.Fatal("a superuser UPDATE of one row's target verified as valid; the chain does not detect a column edit")
	}
	if v.FirstInvalidSeq != 2 {
		t.Fatalf("expected first_invalid_seq 2, got %d (%s)", v.FirstInvalidSeq, v.Kind)
	}
	if v.Kind != audit.FindingHashMismatch {
		t.Fatalf("expected hash_mismatch, got %s", v.Kind)
	}
}

// TestSuperuserTamperAndHashRewriteIsDetected: the attacker also recomputes the row's
// hash, so the row is self-consistent. The prev_hash link and the head still catch it.
func TestSuperuserTamperAndHashRewriteIsDetected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	// Read the row, tamper it, recompute its hash, write both back. This is the
	// strongest single-row tamper possible.
	stored, err := h.reader.ScanScope(ctx, h.scope, 0, 100)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	victim := stored[1] // seq 2
	victim.Target = "x"
	newHash := victim.ComputeHash()

	if _, err := h.owner.Exec(ctx,
		`UPDATE audit_events SET target = 'x', hash = $2 WHERE scope = $1 AND seq = 2`,
		h.scope, newHash,
	); err != nil {
		t.Fatalf("the superuser tamper did not apply: %v", err)
	}

	v := h.verify(t)
	if v.Valid {
		t.Fatal("a row edited together with its hash verified as valid; the chain does not check linkage")
	}
	// Seq 3 still points at the ORIGINAL seq-2 hash, so the break is detected there.
	if v.FirstInvalidSeq != 3 || v.Kind != audit.FindingPrevHashMismatch {
		t.Fatalf("expected prev_hash_mismatch at seq 3, got seq=%d kind=%s", v.FirstInvalidSeq, v.Kind)
	}
}

// TestSuperuserDeleteMiddleRowIsDetected: deleting a row leaves a gap.
func TestSuperuserDeleteMiddleRowIsDetected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	if _, err := h.owner.Exec(ctx,
		`DELETE FROM audit_events WHERE scope = $1 AND seq = 3`, h.scope,
	); err != nil {
		t.Fatalf("the superuser delete did not apply: %v", err)
	}

	v := h.verify(t)
	if v.Valid {
		t.Fatal("deleting a middle row verified as valid")
	}
	if v.FirstInvalidSeq != 3 || v.Kind != audit.FindingMissingSeq {
		t.Fatalf("expected missing_seq at seq 3, got seq=%d kind=%s", v.FirstInvalidSeq, v.Kind)
	}
}

// TestSuperuserHeadRewriteIsDetected: rewriting audit_heads so it no longer describes
// the chain is its own finding.
func TestSuperuserHeadRewriteIsDetected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	t.Run("hash_rewritten", func(t *testing.T) {
		original := strings.Repeat("a", 64)
		if _, err := h.owner.Exec(ctx,
			`UPDATE audit_heads SET hash = $2 WHERE scope = $1`, h.scope, original,
		); err != nil {
			t.Fatalf("the head rewrite did not apply: %v", err)
		}
		v := h.verify(t)
		if v.Valid || v.Kind != audit.FindingHeadMismatch || v.FirstInvalidSeq != 4 {
			t.Fatalf("expected head_mismatch at seq 4, got valid=%v seq=%d kind=%s", v.Valid, v.FirstInvalidSeq, v.Kind)
		}
	})

	t.Run("seq_rewritten_below_events", func(t *testing.T) {
		// The head claims fewer events than exist: an append that did not advance it.
		if _, err := h.owner.Exec(ctx,
			`UPDATE audit_heads SET seq = 2 WHERE scope = $1`, h.scope,
		); err != nil {
			t.Fatalf("the head rewrite did not apply: %v", err)
		}
		v := h.verify(t)
		if v.Valid || v.Kind != audit.FindingEventsAheadOfHead {
			t.Fatalf("expected events_ahead_of_head, got valid=%v kind=%s", v.Valid, v.Kind)
		}
		if v.FirstInvalidSeq != 3 {
			t.Fatalf("expected the first unaccounted sequence to be 3, got %d", v.FirstInvalidSeq)
		}
	})

	t.Run("seq_rewritten_above_events", func(t *testing.T) {
		// The head claims more events than exist: truncation of the tail.
		if _, err := h.owner.Exec(ctx,
			`UPDATE audit_heads SET seq = 9 WHERE scope = $1`, h.scope,
		); err != nil {
			t.Fatalf("the head rewrite did not apply: %v", err)
		}
		v := h.verify(t)
		if v.Valid || v.Kind != audit.FindingEventsBehindHead {
			t.Fatalf("expected events_behind_head, got valid=%v kind=%s", v.Valid, v.Kind)
		}
		if v.FirstInvalidSeq != 5 {
			t.Fatalf("expected the first missing sequence to be 5, got %d", v.FirstInvalidSeq)
		}
	})
}

// TestSuperuserTailTruncationIsDetected: deleting the last rows is caught by the head,
// which still remembers them.
func TestSuperuserTailTruncationIsDetected(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	if _, err := h.owner.Exec(ctx,
		`DELETE FROM audit_events WHERE scope = $1 AND seq >= 4`, h.scope,
	); err != nil {
		t.Fatalf("the truncation did not apply: %v", err)
	}

	v := h.verify(t)
	if v.Valid || v.Kind != audit.FindingEventsBehindHead {
		t.Fatalf("expected events_behind_head, got valid=%v kind=%s", v.Valid, v.Kind)
	}
	if v.FirstInvalidSeq != 4 {
		t.Fatalf("expected the first missing sequence to be 4, got %d", v.FirstInvalidSeq)
	}
}

// TestRuntimeRoleCannotTamper proves the append-only trigger and the grants hold for
// the role the server actually runs as. This is the control that makes the tamper
// probes above require a superuser in the first place.
func TestRuntimeRoleCannotTamper(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	h.mustAppend(t, "project/p/env/e/key/PROTECTED")

	// The runtime pool. In this harness it may be the owner role when
	// COFFER_APP_DB_PASSWORD is unset, in which case the trigger deliberately allows
	// the update (so restore.sh can reproduce a tampered dump). Skip in that case
	// rather than assert something the schema does not promise.
	var isSuper bool
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		t.Fatalf("could not read the runtime role: %v", err)
	}
	if isSuper {
		t.Skip("the runtime pool is the owner role; the append-only trigger permits superuser tampering by design, so this assertion needs COFFER_TEST_APP_DATABASE_URL")
	}

	if _, err := h.db.Pool().Exec(ctx,
		`UPDATE audit_events SET target = 'x' WHERE scope = $1 AND seq = 1`, h.scope,
	); err == nil {
		t.Fatal("the runtime role was able to UPDATE an audit row; the append-only trigger is not enforcing")
	}
	if _, err := h.db.Pool().Exec(ctx,
		`DELETE FROM audit_events WHERE scope = $1 AND seq = 1`, h.scope,
	); err == nil {
		t.Fatal("the runtime role was able to DELETE an audit row; the append-only trigger is not enforcing")
	}

	// The chain must still be intact after the refused attempts.
	if v := h.verify(t); !v.Valid {
		t.Fatalf("the chain was damaged by a refused tamper: %s", v.Describe())
	}
}

// TestVerifyDoesNotModify: verification is read-only. A valid chain verified twice is
// byte-identical, and the head is untouched.
func TestVerifyDoesNotModify(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		h.mustAppend(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	before, err := h.reader.ScanScope(ctx, h.scope, 0, 100)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	headBefore, err := h.reader.Head(ctx, h.scope)
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if v := h.verify(t); !v.Valid {
			t.Fatalf("verification %d failed: %s", i, v.Describe())
		}
	}

	after, err := h.reader.ScanScope(ctx, h.scope, 0, 100)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	headAfter, err := h.reader.Head(ctx, h.scope)
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}

	if len(before) != len(after) {
		t.Fatalf("verification changed the number of events: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Hash != after[i].Hash || before[i].Target != after[i].Target {
			t.Fatalf("verification modified event seq %d", before[i].Seq)
		}
	}
	if headBefore != headAfter {
		t.Fatalf("verification modified the head: %+v -> %+v", headBefore, headAfter)
	}
}

// TestScopesAreIndependent: two chains in one database are separate sequences, and
// damaging one does not affect the other.
//
// The test uses two unique scopes rather than the literal platform scope, on purpose:
// the platform chain is a long-lived shared chain, and a test that asserted it was
// pristine would fail on any database that had ever held a bad row — which is exactly
// what verification is supposed to report. Chain isolation does not depend on the
// scope's name.
func TestScopesAreIndependent(t *testing.T) {
	h := newDBHarness(t)
	ctx := context.Background()

	otherScope := h.scope + "_other"
	otherEvents := []audit.Event{
		{Scope: otherScope, Timestamp: time.Now().UTC(), ActorKind: audit.ActorAnonymous,
			Action: audit.ActionLoginFailure, Target: "auth/token", Result: audit.ResultFailed},
		{Scope: otherScope, Timestamp: time.Now().UTC(), ActorKind: audit.ActorAnonymous,
			Action: audit.ActionLoginFailure, Target: "auth/token", Result: audit.ResultFailed},
	}
	for _, ev := range otherEvents {
		if _, err := h.appender.Append(ctx, ev); err != nil {
			t.Fatalf("append to the second scope failed: %v", err)
		}
	}
	h.mustAppend(t, "project/p/env/e/key/ORG_ONE")

	// Both chains verify independently, and each starts at 1.
	orgVerdict := h.verify(t)
	if !orgVerdict.Valid || orgVerdict.Events != 1 {
		t.Fatalf("the first chain should hold exactly 1 event: %s", orgVerdict.Describe())
	}
	otherVerdict, err := audit.Verify(ctx, h.reader, otherScope)
	if err != nil {
		t.Fatalf("Verify on the second chain failed: %v", err)
	}
	if !otherVerdict.Valid || otherVerdict.Events != 2 {
		t.Fatalf("the second chain should hold exactly 2 events: %s", otherVerdict.Describe())
	}
	// Each chain's first event links to genesis: they are two chains, not one.
	if otherVerdict.TailSeq != 2 || orgVerdict.TailSeq != 1 {
		t.Fatalf("the chains are not independent: first tail %d, second tail %d", orgVerdict.TailSeq, otherVerdict.TailSeq)
	}

	// Neither chain contains the other's events.
	firstEvents, err := h.reader.List(ctx, auditq.Filter{Scope: h.scope})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	for _, e := range firstEvents {
		if e.Action == audit.ActionLoginFailure {
			t.Fatal("the first chain contains an event from the second; the scopes are not isolated")
		}
	}
	secondEvents, err := h.reader.List(ctx, auditq.Filter{Scope: otherScope})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	for _, e := range secondEvents {
		if e.Action == audit.ActionSecretRead {
			t.Fatal("the second chain contains an event from the first; the scopes are not isolated")
		}
	}
}
