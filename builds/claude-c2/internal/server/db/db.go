// Package db manages the Postgres connection pools, embedded migrations, the
// restricted application role, the master-key canary/rotation and the
// platform-admin bootstrap.
package db

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationLock = 7420001

// Connect opens a pool for dsn, retrying until ctx ends. Each attempt is
// logged at most every few seconds.
func Connect(ctx context.Context, dsn string, maxConns int32, log *slog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	return ConnectConfig(ctx, cfg, maxConns, log)
}

// ConnectConfig is Connect with a parsed config.
func ConnectConfig(ctx context.Context, cfg *pgxpool.Config, maxConns int32, log *slog.Logger) (*pgxpool.Pool, error) {
	cfg.MaxConns = maxConns
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 15 * time.Second
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "coffer-server"
	delay := 250 * time.Millisecond
	for attempt := 1; ; attempt++ {
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = pool.Ping(pctx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		if log != nil && (attempt == 1 || attempt%10 == 0) {
			log.Warn("database not reachable yet, retrying", "attempt", attempt, "error", safeErr(err))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

// safeErr strips anything after the first line and never includes the DSN
// (pgx does not include passwords in its errors, but be conservative).
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// Migrate applies embedded migrations under an advisory lock, each in its
// own transaction, recording them in schema_migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		m := migrationNameRE.FindStringSubmatch(f)
		if m == nil {
			return fmt.Errorf("bad migration file name %q", f)
		}
		v, _ := strconv.Atoi(m[1])
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, v).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := migrationFS.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %04d failed: %w", v, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, now()) ON CONFLICT DO NOTHING`, v); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

var migrationNameRE = regexp.MustCompile(`^migrations/(\d{4})_[a-z0-9_]+\.sql$`)

// LatestMigration returns the highest embedded migration version.
func LatestMigration() int {
	files, _ := fs.Glob(migrationFS, "migrations/*.sql")
	latest := 0
	for _, f := range files {
		if m := migrationNameRE.FindStringSubmatch(f); m != nil {
			if v, _ := strconv.Atoi(m[1]); v > latest {
				latest = v
			}
		}
	}
	return latest
}

// MigrationsApplied reports whether q's database has every embedded
// migration applied. A missing schema_migrations table is an error.
func MigrationsApplied(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}) (bool, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version <= $1`, LatestMigration()).Scan(&n); err != nil {
		return false, err
	}
	files, _ := fs.Glob(migrationFS, "migrations/*.sql")
	return n >= len(files), nil
}

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// AppRolePassword derives the restricted role's password from the database
// canary secret (which survives master-key rotation, backup and restore) so
// that every boot against the same database sets the same password. A second
// server process, or a refused boot, therefore never invalidates the
// credentials a running server uses for new pool connections.
func AppRolePassword(canary []byte, dbName, role string) string {
	m := hmac.New(sha256.New, canary)
	m.Write([]byte("coffer/app-role-password/v1|" + dbName + "|" + role))
	return hex.EncodeToString(m.Sum(nil))
}

// SetupAppRole creates (if needed) the restricted login role, sets its
// password (derived from canary, see AppRolePassword), (re-)applies its
// privileges and returns a pool config connecting as that role. Privileges
// are re-applied on every boot because restored dumps are made with
// --no-owner --no-privileges. It must only run after CheckMasterKey
// succeeded, so a refused boot changes nothing.
func SetupAppRole(ctx context.Context, owner *pgxpool.Pool, ownerDSN, role string, canary []byte) (*pgxpool.Config, error) {
	if !roleNameRE.MatchString(role) {
		return nil, errors.New("invalid app role name")
	}
	if len(canary) < 16 {
		return nil, errors.New("app role secret unavailable")
	}
	ident := pgx.Identifier{role}.Sanitize()

	conn, err := owner.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)

	var dbName, currentUser string
	if err := conn.QueryRow(ctx, `SELECT current_database(), current_user`).Scan(&dbName, &currentUser); err != nil {
		return nil, err
	}
	if currentUser == role {
		return nil, errors.New("owner connection already uses the app role")
	}
	password := AppRolePassword(canary, dbName, role)
	verifier := scramVerifier(password)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
		return nil, err
	}
	// The verifier is a SCRAM-SHA-256 hash; the plaintext password never
	// reaches the server or its logs.
	pwLit := "'" + verifier + "'"
	if !exists {
		if _, err := tx.Exec(ctx, `CREATE ROLE `+ident+` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD `+pwLit); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Exec(ctx, `ALTER ROLE `+ident+` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD `+pwLit); err != nil {
			return nil, err
		}
	}
	dbIdent := pgx.Identifier{dbName}.Sanitize()
	stmts := []string{
		`GRANT CONNECT ON DATABASE ` + dbIdent + ` TO ` + ident,
		`GRANT USAGE ON SCHEMA public TO ` + ident,
		`REVOKE CREATE ON SCHEMA public FROM ` + ident,
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ` + ident,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + ident,
		`REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM ` + ident,
		`REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON schema_migrations FROM ` + ident,
		`REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON master_key_check FROM ` + ident,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	cfg, err := pgxpool.ParseConfig(ownerDSN)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = password
	return cfg, nil
}

// scramVerifier builds a SCRAM-SHA-256 verifier for password (RFC 5802/7677).
func scramVerifier(password string) string {
	salt := crypto.RandomBytes(16)
	const iter = 4096
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		panic(err)
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b64(salt), b64(storedKey[:]), b64(serverKey))
}

// ErrMasterKeyMismatch means neither the current nor the previous master key
// matches the database canary.
var ErrMasterKeyMismatch = errors.New("master key does not match database")

// CheckMasterKey verifies the canary and performs rotation (CONTRACT §4). It
// returns the canary plaintext: a random per-database secret that is stable
// across master-key rotation (it is re-sealed, never regenerated).
func CheckMasterKey(ctx context.Context, pool *pgxpool.Pool, current, previous []byte, log *slog.Logger) ([]byte, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock+1); err != nil {
		return nil, err
	}
	var wrapped []byte
	err = tx.QueryRow(ctx, `SELECT wrapped FROM master_key_check WHERE id=1 FOR UPDATE`).Scan(&wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		// Fresh database. If projects already exist (e.g. a restore that lost
		// the canary), refuse unless every DEK unwraps with the current key.
		if err := verifyAllDEKs(ctx, tx, current); err != nil {
			return nil, err
		}
		canary := crypto.RandomBytes(32)
		c, err := crypto.Seal(current, canary, crypto.CanaryAAD())
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO master_key_check (id, wrapped) VALUES (1, $1)`, c); err != nil {
			return nil, err
		}
		return canary, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	if canary, err := crypto.Open(current, wrapped, crypto.CanaryAAD()); err == nil {
		if previous != nil {
			// Finish any partially rotated rows (idempotent).
			if n, err := rewrapDEKs(ctx, tx, current, previous); err != nil {
				return nil, err
			} else if n > 0 && log != nil {
				log.Info("re-wrapped data keys under the current master key", "count", n)
			}
			return canary, tx.Commit(ctx)
		}
		return canary, nil
	}
	if previous == nil {
		return nil, ErrMasterKeyMismatch
	}
	canary, err := crypto.Open(previous, wrapped, crypto.CanaryAAD())
	if err != nil {
		return nil, ErrMasterKeyMismatch
	}
	n, err := rewrapDEKs(ctx, tx, current, previous)
	if err != nil {
		return nil, err
	}
	c, err := crypto.Seal(current, canary, crypto.CanaryAAD())
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE master_key_check SET wrapped=$1 WHERE id=1`, c); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("master key rotated", "data_keys_rewrapped", n)
	}
	return canary, nil
}

func rewrapDEKs(ctx context.Context, tx pgx.Tx, current, previous []byte) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id, org_id, wrapped_dek FROM projects ORDER BY id FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id, org string
		w       []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.org, &r.w); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range all {
		aad := crypto.DEKAAD(r.org, r.id)
		if _, err := crypto.Open(current, r.w, aad); err == nil {
			continue
		}
		dek, err := crypto.Open(previous, r.w, aad)
		if err != nil {
			return 0, fmt.Errorf("project %s: data key unwraps with neither master key", r.id)
		}
		nw, err := crypto.Seal(current, dek, aad)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET wrapped_dek=$1 WHERE id=$2`, nw, r.id); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func verifyAllDEKs(ctx context.Context, tx pgx.Tx, current []byte) error {
	rows, err := tx.Query(ctx, `SELECT id, org_id, wrapped_dek FROM projects`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, org string
		var w []byte
		if err := rows.Scan(&id, &org, &w); err != nil {
			return err
		}
		if _, err := crypto.Open(current, w, crypto.DEKAAD(org, id)); err != nil {
			return ErrMasterKeyMismatch
		}
	}
	return rows.Err()
}

// Bootstrap creates the platform admin if the users table is empty.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, email, passwordHash string) (bool, error) {
	norm := strings.ToLower(strings.TrimSpace(email))
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock+2); err != nil {
		return false, err
	}
	var any bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&any); err != nil {
		return false, err
	}
	if any {
		return false, nil
	}
	id := crypto.NewID("usr")
	if _, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, email, email_norm, password_hash, role, must_change_password)
		VALUES ($1, NULL, $2, $3, $4, 'platform_admin', false)`, id, strings.TrimSpace(email), norm, passwordHash); err != nil {
		return false, err
	}
	if err := audit.AppendTx(ctx, tx, &audit.Event{
		Chain: audit.PlatformChain, ActorType: "system", ActorID: "system", Action: "platform.bootstrap",
		Target: id, Result: audit.Success,
	}); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
