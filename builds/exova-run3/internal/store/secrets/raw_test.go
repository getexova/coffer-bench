package secrets_test

// This file tests the version allocator and the two-person rule directly against a migrated
// database, with no HTTP server and no bootstrap admin.
//
// The testutil harness mints every token through the real login route, which needs the bootstrap
// admin to exist. These tests do not depend on that path: they seed the minimum rows the allocator
// and the approval transaction touch (an organization, a user, a project, an environment) and drive
// the store directly. That keeps the riskiest logic in the product covered independently of the
// authentication slice, and a failure here points at the allocator rather than at login.

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/crypto"
	"coffer/internal/idgen"
	"coffer/internal/store"
	"coffer/internal/store/secrets"
	"coffer/internal/testutil"
)

// rawFixture is a seeded environment reachable without the HTTP layer.
type rawFixture struct {
	store  *secrets.Store
	db     *store.DB
	scope  secrets.Scope
	orgID  string
	userID string
	actor  secrets.ActorRef
}

// newRawFixture migrates the test database and seeds one organization, user, project and
// environment. protected selects the environment's protected flag.
func newRawFixture(t *testing.T, protected bool) *rawFixture {
	t.Helper()
	ctx := context.Background()
	dsn := rawDatabase(t, testutil.TestDatabaseURL(t))

	cfg := rawConfig(t, dsn)
	migrateSerialized(t, dsn, cfg, discardLogger())
	db, err := store.Connect(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	pool := db.Pool()
	orgID := idgen.New("org")
	userID := idgen.New("usr")
	projectID := idgen.New("prj")
	envID := idgen.New("env")
	envSlug := "dev"
	if protected {
		envSlug = "prod"
	}

	// The password hash is a placeholder: nothing logs in here.
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, slug) VALUES ($1, $2)`, orgID, orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, 'x', 'owner')`,
		userID, orgID, userID+"@raw.invalid"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, org_id, slug) VALUES ($1, $2, 'rawproj')`,
		projectID, orgID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, $3, $4)`,
		envID, projectID, envSlug, protected); err != nil {
		t.Fatalf("seed environment: %v", err)
	}

	// Clean up in dependency order, so repeated runs stay isolated.
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM change_requests WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM secret_versions WHERE secret_id IN
			(SELECT s.id FROM secrets s JOIN environments e ON e.id = s.env_id WHERE e.project_id = $1)`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM secrets WHERE env_id IN
			(SELECT id FROM environments WHERE project_id = $1)`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM project_data_keys WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM environments WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	sealer, err := crypto.NewSealerFromBytes(cfg.MasterKey)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	return &rawFixture{
		store:  secrets.New(store.NewBase(db), sealer),
		db:     db,
		orgID:  orgID,
		userID: userID,
		actor:  secrets.ActorRef{ID: userID, Kind: "user"},
		scope: secrets.Scope{
			OrgID:     orgID,
			ProjectID: projectID,
			EnvID:     envID,
			EnvSlug:   envSlug,
			Protected: protected,
			Grant:     "writer",
		},
	}
}

// rawDatabase returns a connection string for a database private to these tests.
//
// It exists because authapi.Bootstrap creates the platform admin only when no users exist at all.
// These fixtures insert users directly, so sharing the harness database would let a raw test that
// runs first suppress the bootstrap and break every login-based test in the run. A separate
// database removes the interference in both directions.
func rawDatabase(t *testing.T, baseDSN string) string {
	t.Helper()
	u, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	const name = "coffer_raw_test"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect to create the raw test database: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	// CREATE DATABASE has no IF NOT EXISTS; a duplicate name is the expected case on a rerun.
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("create raw test database: %v", err)
		}
	}
	u.Path = "/" + name
	return u.String()
}

// rawConfig builds a valid config pointing at the test database in the gated degraded single-role
// mode, which is allowed outside production and needs no coffer_app password.
func rawConfig(t *testing.T, dsn string) *config.Config {
	t.Helper()
	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		switch key {
		case "COFFER_MASTER_KEY":
			// A fixed test key (32 bytes, base64). Not a real credential: this is a throwaway
			// test database and the key never protects anything but these fixtures.
			return "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", true
		case "COFFER_BOOTSTRAP_ADMIN_EMAIL":
			return "raw@raw.invalid", true
		case "COFFER_BOOTSTRAP_ADMIN_PASSWORD":
			return "raw-fixture-password", true
		case "COFFER_ENV":
			return "development", true
		case "COFFER_ALLOW_DEGRADED_DB_ROLE":
			return "1", true
		case "COFFER_MIGRATION_DATABASE_URL":
			return dsn, true
		case "DATABASE_URL":
			return dsn, true
		case "POSTGRES_DB":
			return "coffer_test", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// discardLogger keeps migration output out of the test log.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestRawConcurrentUnconditionalWrites is the allocator test with no HTTP dependency: concurrent
// unconditional writes each get a distinct, gap-free version and none is lost.
func TestRawConcurrentUnconditionalWrites(t *testing.T) {
	f := newRawFixture(t, false)
	ctx := context.Background()
	const key = "RAW_CONCURRENT"
	const writers = 40

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		versions = make(map[int64]string, writers)
		errs     []error
	)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			value := string(rune('a'+i%26)) + "-value"
			applied, err := f.store.Apply(ctx, secrets.WriteRequest{
				Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte(value), Actor: f.actor,
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if prev, dup := versions[applied.Version]; dup {
				errs = append(errs, errDuplicate(applied.Version, prev, value))
				return
			}
			versions[applied.Version] = value
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Error(err)
	}
	if len(versions) != writers {
		t.Fatalf("%d writers produced %d distinct versions", writers, len(versions))
	}
	for v := int64(1); v <= writers; v++ {
		if _, ok := versions[v]; !ok {
			t.Errorf("version %d missing: the allocator produced a gap", v)
		}
	}

	// Every version still holds the value its own writer wrote: no lost updates.
	for v, want := range versions {
		got, err := f.store.ValueAt(ctx, f.scope, key, v)
		if err != nil {
			t.Fatalf("value at %d: %v", v, err)
		}
		if string(got.Value) != want {
			t.Fatalf("version %d holds %q, want %q", v, got.Value, want)
		}
	}

	current, _, found, err := f.store.CurrentVersion(ctx, f.scope, key)
	if err != nil || !found {
		t.Fatalf("current version: %v", err)
	}
	if current != writers {
		t.Fatalf("current_version = %d, want %d", current, writers)
	}

	var rows int
	if err := f.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM secret_versions sv JOIN secrets s ON s.id = sv.secret_id
		  WHERE s.env_id = $1 AND s.key = $2`, f.scope.EnvID, key).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != writers {
		t.Fatalf("%d secret_versions rows, want %d", rows, writers)
	}
}

type duplicateVersionError struct {
	version       int64
	first, second string
}

func (e duplicateVersionError) Error() string {
	return "duplicate version " + itoa(e.version) + ": " + e.first + " and " + e.second
}

func errDuplicate(version int64, first, second string) error {
	return duplicateVersionError{version: version, first: first, second: second}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestRawExpectedVersionConflict covers the conditional write with no HTTP dependency.
func TestRawExpectedVersionConflict(t *testing.T) {
	f := newRawFixture(t, false)
	ctx := context.Background()
	const key = "RAW_EXPECT"

	if _, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("one"), Actor: f.actor,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	wrong := int64(5)
	if _, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("two"),
		ExpectedVersion: &wrong, Actor: f.actor,
	}); err != secrets.ErrConflict {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if current, _, _, _ := f.store.CurrentVersion(ctx, f.scope, key); current != 1 {
		t.Fatalf("a rejected write consumed a version: current = %d", current)
	}
	if v, err := f.store.Value(ctx, f.scope, key); err != nil || string(v.Value) != "one" {
		t.Fatalf("a rejected write changed the value: %q, %v", v.Value, err)
	}

	right := int64(1)
	applied, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("two"),
		ExpectedVersion: &right, Actor: f.actor,
	})
	if err != nil || applied.Version != 2 {
		t.Fatalf("conditional write: %v, version %d", err, applied.Version)
	}
}

// TestRawTombstoneAndRollback covers tombstones and rollback numbering with no HTTP dependency.
func TestRawTombstoneAndRollback(t *testing.T) {
	f := newRawFixture(t, false)
	ctx := context.Background()
	const key = "RAW_LIFECYCLE"

	for _, v := range []string{"one", "two"} {
		if _, err := f.store.Apply(ctx, secrets.WriteRequest{
			Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte(v), Actor: f.actor,
		}); err != nil {
			t.Fatalf("set %s: %v", v, err)
		}
	}

	// Delete writes a tombstone at version 3.
	del, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpDelete, Actor: f.actor,
	})
	if err != nil || del.Version != 3 {
		t.Fatalf("delete: %v, version %d", err, del.Version)
	}
	if _, err := f.store.Value(ctx, f.scope, key); err != secrets.ErrNotFound {
		t.Fatalf("get after delete: %v, want ErrNotFound", err)
	}
	history, err := f.store.History(ctx, f.scope, key)
	if err != nil || len(history) != 3 || !history[2].Deleted {
		t.Fatalf("history after delete: %+v, %v", history, err)
	}

	// Rollback to version 1 creates version 4 holding version 1's value.
	rb, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpRollback, TargetVersion: 1, Actor: f.actor,
	})
	if err != nil || rb.Version != 4 {
		t.Fatalf("rollback: %v, version %d", err, rb.Version)
	}
	got, err := f.store.Value(ctx, f.scope, key)
	if err != nil || string(got.Value) != "one" || got.Version != 4 {
		t.Fatalf("after rollback: %q v%d, %v", got.Value, got.Version, err)
	}

	// Rolling back to a tombstone has no value to copy.
	if _, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpRollback, TargetVersion: 3, Actor: f.actor,
	}); err != secrets.ErrNotFound {
		t.Fatalf("rollback to a tombstone: %v, want ErrNotFound", err)
	}
}

// TestRawApprovalCannotApplyTwice is the two-person rule with no HTTP dependency: self-approval is
// refused without consuming the request, the first approval applies it, and every later attempt is
// ErrAlreadyResolved with no second version written.
func TestRawApprovalCannotApplyTwice(t *testing.T) {
	f := newRawFixture(t, true)
	ctx := context.Background()
	const key = "RAW_APPROVAL"

	ch, err := f.store.CreateChange(ctx, secrets.Proposal{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("proposed"),
		BaseVer: 0, Proposer: f.actor,
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	// Self-approval: 403 semantics, nothing consumed.
	if _, err := approveRaw(f, ch, f.actor); err != secrets.ErrSelfApproval {
		t.Fatalf("self approval: %v, want ErrSelfApproval", err)
	}
	if after, err := f.store.GetChange(ctx, f.orgID, ch.ID); err != nil || after.Status != secrets.StatusPending {
		t.Fatalf("after self-approval attempt: %q, %v", after.Status, err)
	}

	approver := f.extraApprover(t, "one")
	applied, err := approveRaw(f, ch, approver)
	if err != nil || applied.Version != 1 {
		t.Fatalf("first approval: %v, version %d", err, applied.Version)
	}

	// Every subsequent resolution is a conflict, from any approver.
	for i, label := range []string{"one", "two", "three"} {
		if _, err := approveRaw(f, ch, f.extraApprover(t, label)); err != secrets.ErrAlreadyResolved {
			t.Fatalf("attempt %d: %v, want ErrAlreadyResolved", i, err)
		}
	}
	if current, _, _, _ := f.store.CurrentVersion(ctx, f.scope, key); current != 1 {
		t.Fatalf("current_version = %d, want 1: the change was applied more than once", current)
	}
	after, err := f.store.GetChange(ctx, f.orgID, ch.ID)
	if err != nil {
		t.Fatalf("get change: %v", err)
	}
	if after.ResolverID != approver.ID {
		t.Fatalf("resolver = %q, want %q", after.ResolverID, approver.ID)
	}
}

// TestRawConcurrentApprovalAppliesOnce races many approvers against one request.
func TestRawConcurrentApprovalAppliesOnce(t *testing.T) {
	f := newRawFixture(t, true)
	ctx := context.Background()
	const key = "RAW_RACE"

	ch, err := f.store.CreateChange(ctx, secrets.Proposal{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("race"),
		BaseVer: 0, Proposer: f.actor,
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	const approvers = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		conflicts int
		other     []error
	)
	start := make(chan struct{})
	for i := 0; i < approvers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := approveRaw(f, ch, f.extraApprover(t, "race-"+itoa(int64(i))))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case err == secrets.ErrAlreadyResolved:
				conflicts++
			default:
				other = append(other, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected error: %v", err)
	}
	if successes != 1 {
		t.Fatalf("%d approvals succeeded, want exactly 1", successes)
	}
	if conflicts != approvers-1 {
		t.Fatalf("%d conflicts, want %d", conflicts, approvers-1)
	}
	if current, _, _, _ := f.store.CurrentVersion(ctx, f.scope, key); current != 1 {
		t.Fatalf("current_version = %d, want 1", current)
	}
}

// TestRawStaleApproval covers staleness with no HTTP dependency: an intervening write makes the
// approval a conflict, the request is marked stale, and nothing is applied.
func TestRawStaleApproval(t *testing.T) {
	f := newRawFixture(t, true)
	ctx := context.Background()
	const key = "RAW_STALE"

	if _, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("first"), Actor: f.actor,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ch, err := f.store.CreateChange(ctx, secrets.Proposal{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("proposed"),
		BaseVer: 1, Proposer: f.actor,
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	// The key moves while the request is pending.
	if _, err := f.store.Apply(ctx, secrets.WriteRequest{
		Scope: f.scope, Key: key, Op: secrets.OpSet, Value: []byte("intervening"), Actor: f.actor,
	}); err != nil {
		t.Fatalf("intervening write: %v", err)
	}

	if _, err := approveRaw(f, ch, f.extraApprover(t, "stale")); err != secrets.ErrStale {
		t.Fatalf("stale approval: %v, want ErrStale", err)
	}
	after, err := f.store.GetChange(ctx, f.orgID, ch.ID)
	if err != nil || after.Status != secrets.StatusStale {
		t.Fatalf("status = %q, want stale (the mark must survive the 409)", after.Status)
	}
	got, err := f.store.Value(ctx, f.scope, key)
	if err != nil || string(got.Value) != "intervening" || got.Version != 2 {
		t.Fatalf("after a stale approval: %q v%d, %v", got.Value, got.Version, err)
	}
	// A stale request cannot be resolved afterwards.
	if _, err := approveRaw(f, ch, f.extraApprover(t, "stale-2")); err != secrets.ErrAlreadyResolved {
		t.Fatalf("approving a stale request: %v, want ErrAlreadyResolved", err)
	}
}

// TestRawCopiedCiphertextFails is the AAD copy-failure test through the real schema: a ciphertext
// moved to another key's row must fail to decrypt and must return no value.
func TestRawCopiedCiphertextFails(t *testing.T) {
	f := newRawFixture(t, false)
	ctx := context.Background()

	for _, k := range []string{"RAW_SOURCE", "RAW_TARGET"} {
		if _, err := f.store.Apply(ctx, secrets.WriteRequest{
			Scope: f.scope, Key: k, Op: secrets.OpSet, Value: []byte("value-of-" + k), Actor: f.actor,
		}); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}

	if _, err := f.db.Pool().Exec(ctx, `
UPDATE secret_versions t
   SET ciphertext = s.ciphertext, nonce = s.nonce
  FROM secret_versions s, secrets ks, secrets kt
 WHERE ks.env_id = $1 AND ks.key = 'RAW_SOURCE'
   AND kt.env_id = $1 AND kt.key = 'RAW_TARGET'
   AND s.secret_id = ks.id AND s.version = ks.current_version
   AND t.secret_id = kt.id AND t.version = kt.current_version`, f.scope.EnvID); err != nil {
		t.Fatalf("copy ciphertext: %v", err)
	}

	got, err := f.store.Value(ctx, f.scope, "RAW_TARGET")
	if err == nil {
		t.Fatalf("a copied ciphertext decrypted and returned %q", got.Value)
	}
	if len(got.Value) != 0 {
		t.Fatalf("a failed decrypt returned a value: %q", got.Value)
	}
	// The source is unaffected.
	if v, err := f.store.Value(ctx, f.scope, "RAW_SOURCE"); err != nil || string(v.Value) != "value-of-RAW_SOURCE" {
		t.Fatalf("source key broke: %q, %v", v.Value, err)
	}
}

// extraApprover inserts a second real user and returns it as an actor. Approvers must exist because
// change_requests.resolver_id references users.
func (f *rawFixture) extraApprover(t *testing.T, label string) secrets.ActorRef {
	t.Helper()
	id := idgen.New("usr")
	if _, err := f.db.Pool().Exec(context.Background(),
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, 'x', 'admin')`,
		id, f.orgID, id+"-"+label+"@raw.invalid"); err != nil {
		t.Fatalf("seed approver %s: %v", label, err)
	}
	return secrets.ActorRef{ID: id, Kind: "user"}
}

// approveRaw runs the approval transaction, committing on the stale sentinel.
func approveRaw(f *rawFixture, ch secrets.Change, approver secrets.ActorRef) (secrets.Applied, error) {
	var applied secrets.Applied
	ctx := context.Background()
	err := f.store.InTxWithCommit(ctx, secrets.ErrStale, func(tx pgx.Tx) error {
		var err error
		applied, err = f.store.ApproveTx(ctx, tx, ch, approver, true,
			audit.NopWriter(), audit.Event{Scope: ch.OrgID, ActorID: approver.ID})
		return err
	})
	return applied, err
}

// migrateSerialized applies the migrations while holding a cluster-wide advisory lock.
//
// PostgreSQL roles are cluster-wide, not per-database, so the CREATE ROLE coffer_app block in
// 0001_init.sql collides when two packages migrate different databases in the same cluster at the
// same time ("duplicate key value violates unique constraint pg_authid_rolname_index"). `go test`
// runs packages in parallel and each of this slice's test files migrates its own private database,
// so the migrations are serialised here on the shared database, which every test process can reach.
//
// The lock key is an arbitrary constant; it only has to be the same in every process that migrates
// this cluster.
func migrateSerialized(t *testing.T, targetDSN string, cfg *config.Config, log *slog.Logger) {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("COFFER_TEST_DATABASE_URL"))
	if base == "" {
		t.Fatalf("COFFER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to take the migration lock: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	const lockKey = int64(0x636f6666657231) // "coffe r1"
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatalf("take the migration lock: %v", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
	}()

	if err := store.Migrate(ctx, cfg, log); err != nil {
		t.Fatalf("migrate %s: %v", targetDSN, err)
	}
}
