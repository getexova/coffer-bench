// Package store owns the database: the connection pools, the migration runner and
// the small base type every slice store embeds.
//
// Two connections exist by design. Migrations run as the owner role, which is the
// only role that can create the schema, the roles and the grants. Serving runs as
// coffer_app, which owns nothing, has no CREATE on the schema and cannot UPDATE or
// DELETE the audit log. The owner connection is opened, used and closed before the
// runtime pool exists, so the privileged credential is not held for the life of the
// process.
//
// The migration runner takes a fixed advisory lock before doing anything, so two
// containers starting at the same moment serialise and the loser applies nothing.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/config"
)

// MigrationLockKey is the advisory lock key for the migration runner. Any constant
// works; it must never change, or two versions of the server would not exclude each
// other.
const MigrationLockKey int64 = 0x636f66666572 // "coffer"

// DefaultConnectTimeout bounds a single connection attempt.
const DefaultConnectTimeout = 10 * time.Second

// Pool sizing.
//
// pgxpool's default is max(4, runtime.NumCPU()), which is 16 on a 16-core host. SPEC §5
// asks for 50 concurrent value reads, so the default leaves 50 requests contending for
// 16 connections and queueing on the pool: the measured p95 was a pool ceiling rather
// than the cost of a read, and it grew linearly with concurrency with the knee at
// exactly the default size.
//
// DefaultMaxConns is sized for that documented target with headroom for a burst, and it
// is deliberately bounded. PostgreSQL's own max_connections defaults to 100; an
// unbounded or oversized pool turns a load spike into "too many clients already", which
// is a worse failure than queueing, and it is antisocial on a shared database.
//
// Two Coffer processes (a rolling restart, or a second replica) therefore open at most
// 2*DefaultMaxConns connections between them, which stays inside a default
// max_connections of 100 with room for an operator's own sessions. COFFER_DB_MAX_CONNS
// overrides it for a shared database.
const (
	DefaultMaxConns = int32(32)
	DefaultMinConns = int32(4)
)

// txTimeout bounds a transaction rollback issued after the request context is gone.
const txTimeout = 15 * time.Second

// RetryPolicy controls how long Connect waits for a database that is not up yet.
type RetryPolicy struct {
	// InitialDelay is the first backoff step.
	InitialDelay time.Duration
	// MaxDelay caps the backoff step.
	MaxDelay time.Duration
	// Timeout is the overall budget. A database that has not answered by then
	// is a failed start, not an infinite wait.
	Timeout time.Duration
}

// DefaultRetryPolicy is used by Connect when the caller does not supply one. The
// budget matches the stack's startup tolerance: compose waits 180 s for /readyz, so
// the pool has to survive a database that is still initialising.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		InitialDelay: 250 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Timeout:      120 * time.Second,
	}
}

// DB is the runtime connection pool.
type DB struct {
	pool *pgxpool.Pool
	cfg  *config.Config
	log  *slog.Logger
}

// Pool returns the runtime pool for the slices to query.
func (db *DB) Pool() *pgxpool.Pool {
	if db == nil {
		return nil
	}
	return db.pool
}

// Config returns the configuration the pool was opened with.
func (db *DB) Config() *config.Config {
	if db == nil {
		return nil
	}
	return db.cfg
}

// Close releases the pool.
func (db *DB) Close() {
	if db == nil || db.pool == nil {
		return
	}
	db.pool.Close()
	db.pool = nil
}

// Ping answers SELECT 1 against the runtime pool. /readyz uses it.
func (db *DB) Ping(ctx context.Context) error {
	if db == nil || db.pool == nil {
		return errors.New("store: no database pool")
	}
	var one int
	if err := db.pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("store: database ping: %w", err)
	}
	if one != 1 {
		return errors.New("store: database returned an unexpected value for SELECT 1")
	}
	return nil
}

// ErrMigrationsIncomplete is returned by MigrationsApplied when the runtime pool
// answered but the schema is not at the version this binary expects: the table is
// missing, unreadable, or a version is absent. It is a distinct error so /readyz can
// report reason "migrations" rather than blaming the database, which is answering.
var ErrMigrationsIncomplete = errors.New("store: migrations are not applied")

// MigrationsApplied reports whether every embedded migration version is present in
// schema_migrations. /readyz uses it to distinguish "database" from "migrations":
// reaching this function at all means the pool answered, so any error here is a schema
// problem and wraps ErrMigrationsIncomplete.
func (db *DB) MigrationsApplied(ctx context.Context) error {
	if db == nil || db.pool == nil {
		return errors.New("store: no database pool")
	}
	versions, err := embeddedVersions()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMigrationsIncomplete, err)
	}
	if err := missingVersions(ctx, db.pool, versions); err != nil {
		return fmt.Errorf("%w: %v", ErrMigrationsIncomplete, err)
	}
	return nil
}

// Connect opens the runtime pool, retrying with backoff so the server survives a
// database that is not up yet.
func Connect(ctx context.Context, cfg *config.Config, log *slog.Logger) (*DB, error) {
	return ConnectWithPolicy(ctx, cfg, log, DefaultRetryPolicy())
}

// ConnectWithPolicy is Connect with an explicit retry policy.
func ConnectWithPolicy(ctx context.Context, cfg *config.Config, log *slog.Logger, policy RetryPolicy) (*DB, error) {
	if cfg == nil {
		return nil, errors.New("store: nil config")
	}
	if log == nil {
		log = slog.Default()
	}
	if policy.InitialDelay <= 0 {
		policy.InitialDelay = DefaultRetryPolicy().InitialDelay
	}
	if policy.MaxDelay < policy.InitialDelay {
		policy.MaxDelay = DefaultRetryPolicy().MaxDelay
	}
	if policy.Timeout <= 0 {
		policy.Timeout = DefaultRetryPolicy().Timeout
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.RuntimeURL())
	if err != nil {
		// A malformed URL is a misconfiguration, not a transient failure: retrying
		// it would only delay a message the operator needs now. The URL itself is
		// never printed, because it contains a password.
		return nil, errors.New("store: runtime database URL is not valid")
	}
	poolCfg.MaxConns = cfg.DBMaxConns()
	poolCfg.MinConns = cfg.DBMinConns()
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.HealthCheckPeriod = 30 * time.Second
	poolCfg.ConnConfig.ConnectTimeout = DefaultConnectTimeout

	// MinConns keeps a warm floor so the first burst after a quiet period does not pay
	// connection-establishment cost. Never above MaxConns: pgxpool treats a larger
	// minimum as a configuration error.
	if poolCfg.MinConns > poolCfg.MaxConns {
		poolCfg.MinConns = poolCfg.MaxConns
	}

	deadline := time.Now().Add(policy.Timeout)
	delay := policy.InitialDelay
	attempt := 0

	for {
		attempt++
		pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, DefaultConnectTimeout)
			pingErr := pool.Ping(pingCtx)
			cancel()
			if pingErr == nil {
				db := &DB{pool: pool, cfg: cfg, log: log}
				log.Info("database connected",
					"role", roleOf(cfg),
					"degraded", cfg.Degraded(),
					"attempt", attempt)
				return db, nil
			}
			pool.Close()
			err = pingErr
		}

		// A rejected credential is a misconfiguration, never a transient failure
		// (docs/CONTRACTS.md §11). Retrying cannot fix it and, worse, a retry loop
		// invites a fallback to the owner role. Fail the start, naming the variable
		// the operator has to correct.
		if isAuthFailure(err) {
			if cfg.Degraded() {
				return nil, fmt.Errorf("store: the database rejected the owner credentials used because COFFER_ALLOW_DEGRADED_DB_ROLE is set; refusing to fall back: %w", scrub(err))
			}
			return nil, fmt.Errorf("store: the database rejected the %s credentials from COFFER_APP_DB_PASSWORD; fix the password (the role's password is never rewritten automatically) or unset COFFER_APP_DB_PASSWORD: %w", config.AppDBRole, scrub(err))
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("store: connect cancelled: %w", ctx.Err())
		}
		if time.Now().Add(delay).After(deadline) {
			return nil, fmt.Errorf("store: database did not become reachable within %s (%d attempts): %w", policy.Timeout, attempt, scrub(err))
		}

		log.Warn("database not reachable yet, retrying",
			"attempt", attempt,
			"retry_in_ms", delay.Milliseconds(),
			"role", roleOf(cfg))

		// Jitter so several containers restarting together do not retry in lockstep.
		sleep := delay/2 + time.Duration(rand.Int63n(int64(delay/2)+1))
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("store: connect cancelled: %w", ctx.Err())
		case <-time.After(sleep):
		}

		delay *= 2
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
		}
	}
}

// isAuthFailure reports whether err is the server refusing the credential rather
// than the server being unavailable.
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		switch pgErr.SQLState() {
		case "28P01", // invalid_password
			"28000", // invalid_authorization_specification
			"42501": // insufficient_privilege
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"password authentication failed",
		"role \"",
		"no pg_hba.conf entry",
		"database \"",
	} {
		if strings.Contains(msg, marker) && (strings.Contains(msg, "failed") || strings.Contains(msg, "does not exist")) {
			return true
		}
	}
	return false
}

// scrub removes the connection string and anything that looks like a password from
// an error before it reaches a log or an operator's terminal.
func scrub(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, marker := range []string{"password=", "postgres://", "postgresql://"} {
		if idx := strings.Index(strings.ToLower(msg), marker); idx >= 0 {
			msg = msg[:idx] + "[redacted]"
			break
		}
	}
	return errors.New(msg)
}

func roleOf(cfg *config.Config) string {
	if cfg == nil {
		return "unknown"
	}
	if cfg.Degraded() {
		return "owner (degraded)"
	}
	return config.AppDBRole
}

// Boot runs migrations as the owner, then opens the runtime pool. It is the single
// entry point the server uses.
func Boot(ctx context.Context, cfg *config.Config, log *slog.Logger) (*DB, error) {
	if cfg == nil {
		return nil, errors.New("store: nil config")
	}
	if log == nil {
		log = slog.Default()
	}
	if err := Migrate(ctx, cfg, log); err != nil {
		return nil, err
	}
	return Connect(ctx, cfg, log)
}

// Migrate applies pending migrations as the owner role, sets the coffer_app role
// password when one is configured, and re-applies the grant block. It opens and
// closes its own owner connection.
func Migrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if cfg == nil {
		return errors.New("store: nil config")
	}
	if log == nil {
		log = slog.Default()
	}

	connCfg, err := pgx.ParseConfig(cfg.MigrationURL())
	if err != nil {
		return errors.New("store: migration database URL is not valid")
	}
	connCfg.ConnectTimeout = DefaultConnectTimeout

	conn, err := pgx.ConnectConfig(ctx, connCfg)
	if err != nil {
		if isAuthFailure(err) {
			return fmt.Errorf("store: the database rejected the owner (migration) credentials: %w", scrub(err))
		}
		return fmt.Errorf("store: could not open the migration connection: %w", scrub(err))
	}
	defer func() {
		// The owner connection must not outlive the migration step.
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	if err := runMigrations(ctx, conn, cfg, log); err != nil {
		return err
	}

	log.Info("migrations up to date")
	return nil
}

// runMigrations holds the advisory lock for the whole migration step: apply pending
// files, set the role password, re-apply grants. The lock is released even on
// failure, by deferring it on the session that took it.
func runMigrations(ctx context.Context, conn *pgx.Conn, cfg *config.Config, log *slog.Logger) error {
	locked := false
	defer func() {
		if !locked {
			return
		}
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", MigrationLockKey); err != nil {
			log.Warn("could not release the migration advisory lock", "error", scrub(err))
		}
	}()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", MigrationLockKey); err != nil {
		return fmt.Errorf("store: could not take the migration advisory lock: %w", scrub(err))
	}
	locked = true

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version    bigint PRIMARY KEY,
		  applied_at timestamptz NOT NULL DEFAULT now(),
		  checksum   text NOT NULL
		)`); err != nil {
		return fmt.Errorf("store: could not ensure schema_migrations: %w", scrub(err))
	}

	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}

	owner := currentUser(ctx, conn)

	pending := 0
	for _, m := range migrations {
		if existing, ok := applied[m.Version]; ok {
			// A changed checksum on an applied version means the schema on disk
			// and the schema in the code have diverged. Failing hard is the only
			// safe answer: applying it again could corrupt live data, and
			// ignoring it would serve code written for a different schema.
			if existing != m.Checksum {
				return fmt.Errorf("store: migration %04d_%s has changed since it was applied (recorded checksum %s, file checksum %s); refusing to start",
					m.Version, m.Name, existing, m.Checksum)
			}
			continue
		}
		if err := applyMigration(ctx, conn, m, owner); err != nil {
			return err
		}
		pending++
		log.Info("migration applied", "version", m.Version, "name", m.Name)
	}
	if pending == 0 {
		log.Debug("no pending migrations")
	}

	// The role password and the grants are re-applied on every boot, not only when
	// a migration was pending. A restore from a `pg_dump --no-owner
	// --no-privileges` dump brings schema_migrations back populated with no grants
	// in it, so this is what makes a restored stack usable again.
	if err := ensureAppRole(ctx, conn, cfg, owner); err != nil {
		return err
	}
	if err := applyGrants(ctx, conn, owner); err != nil {
		return err
	}

	return nil
}

// applyMigration runs one file, its grant block and its schema_migrations row inside
// a single transaction, so a failure part way through leaves no partial schema
// (docs/CONTRACTS.md §12).
func applyMigration(ctx context.Context, conn *pgx.Conn, m migration, owner string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: could not begin migration %04d: %w", m.Version, scrub(err))
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: migration %04d_%s failed: %w", m.Version, m.Name, scrub(err))
	}

	// 0001 carries the role and grant block itself, because the block can only run
	// once the tables exist and it must be in the same transaction.
	grants, err := grantsSQL(owner)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, grants); err != nil {
		return fmt.Errorf("store: migration %04d_%s could not apply roles and grants: %w", m.Version, m.Name, scrub(err))
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
		m.Version, m.Checksum,
	); err != nil {
		return fmt.Errorf("store: could not record migration %04d: %w", m.Version, scrub(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: could not commit migration %04d: %w", m.Version, scrub(err))
	}
	return nil
}

// applyGrants re-applies the frozen grant block after every boot's migration step.
func applyGrants(ctx context.Context, conn *pgx.Conn, owner string) error {
	exists, err := tablesExist(ctx, conn)
	if err != nil {
		return err
	}
	if !exists {
		// Nothing to grant on yet; 0001 will have created everything and applied
		// the block itself. Reaching here means 0001 is missing entirely.
		return nil
	}
	grants, err := grantsSQL(owner)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, grants); err != nil {
		return fmt.Errorf("store: could not apply database grants: %w", scrub(err))
	}
	return nil
}

// ensureAppRole sets the coffer_app password from COFFER_APP_DB_PASSWORD. The
// CREATE ROLE in the frozen block has no password, so without this the runtime pool
// could not authenticate as coffer_app.
//
// ALTER ROLE cannot take a bind parameter, so the statement is built by PostgreSQL
// itself with format('%L'), and the password is passed as a parameter. It therefore
// never appears in a log line, an error string or a query plan, and a password
// containing a quote cannot break out of the literal.
func ensureAppRole(ctx context.Context, conn *pgx.Conn, cfg *config.Config, owner string) error {
	if cfg.DB.AppPassword == "" {
		return nil
	}

	provisioned, err := roleHasPassword(ctx, conn)
	if err != nil {
		return err
	}
	if provisioned {
		// The role already has a password, so this boot does NOT touch it. Rewriting
		// it from the environment would turn a typo into a silent privilege change:
		// the wrong password would become the correct one, the operator would never
		// learn, and the role would diverge from whatever the secret store says.
		// docs/CONTRACTS.md §11 requires a rejected credential to be a failed start.
		//
		// Authentication is verified by Connect, which runs immediately after this
		// and fails the boot naming COFFER_APP_DB_PASSWORD if the credential is
		// rejected.
		return nil
	}

	// First provisioning: the role exists but has no password yet. The owner
	// connection is entitled to set it exactly once, here.
	var stmt string
	if err := conn.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)`,
		config.AppDBRole, cfg.DB.AppPassword,
	).Scan(&stmt); err != nil {
		return fmt.Errorf("store: could not prepare the %s role password: %w", config.AppDBRole, scrub(err))
	}

	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("store: could not set the %s role password: %w", config.AppDBRole, scrub(err))
	}
	return nil
}

// roleHasPassword reports whether the runtime role already has a password set.
//
// pg_authid is readable only by a superuser. When it is not readable the answer is
// "yes", which is the conservative direction: the boot then leaves the password
// alone and Connect verifies the credential. Guessing "no" would rewrite the
// password, which is the behaviour this function exists to prevent.
func roleHasPassword(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var hasPassword bool
	err := conn.QueryRow(ctx,
		`SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = $1`,
		config.AppDBRole,
	).Scan(&hasPassword)
	if err == nil {
		return hasPassword, nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		// The role does not exist yet. The grant block creates it, so this means the
		// schema step did not run; treat it as unprovisioned and let the ALTER report
		// the real problem if it cannot create one.
		return false, nil
	}

	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "42501" { // insufficient_privilege
		return true, nil
	}

	return false, fmt.Errorf("store: could not read the %s role state: %w", config.AppDBRole, scrub(err))
}

func tablesExist(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var exists bool
	err := conn.QueryRow(ctx, `
		SELECT to_regclass('public.audit_events') IS NOT NULL
		   AND to_regclass('public.organizations') IS NOT NULL`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: could not inspect the schema: %w", scrub(err))
	}
	return exists, nil
}

func currentUser(ctx context.Context, conn *pgx.Conn) string {
	var user string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&user); err != nil || user == "" {
		return "CURRENT_USER"
	}
	return user
}

func appliedMigrations(ctx context.Context, conn *pgx.Conn) (map[int64]string, error) {
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: could not read schema_migrations: %w", scrub(err))
	}
	defer rows.Close()

	applied := make(map[int64]string)
	for rows.Next() {
		var version int64
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("store: could not read schema_migrations: %w", scrub(err))
		}
		applied[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: could not read schema_migrations: %w", scrub(err))
	}
	return applied, nil
}

// missingVersions checks the embedded set against schema_migrations using whatever
// queryer the caller has: the runtime pool for /readyz, or the owner connection.
func missingVersions(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, versions []int64) error {
	if len(versions) == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		// A missing schema_migrations table means no migration has been applied.
		return errors.New("store: migrations are not applied")
	}
	defer rows.Close()

	present := make(map[int64]bool)
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return errors.New("store: could not read schema_migrations")
		}
		present[version] = true
	}
	if err := rows.Err(); err != nil {
		return errors.New("store: could not read schema_migrations")
	}
	for _, version := range versions {
		if !present[version] {
			return fmt.Errorf("store: migration %d is not applied", version)
		}
	}
	return nil
}
