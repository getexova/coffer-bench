package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/config"
)

// Migrations are embedded, so the binary carries its own schema and cannot start
// against a checkout whose SQL is missing.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// The grant block is embedded separately from the migrations because it is applied
// on every boot, not once per version, and because the migration sorter must only
// ever see numbered files.
//
//go:embed grants.sql
var grantsFile string

// migration is one parsed migration file.
type migration struct {
	Version  int64
	Name     string
	Filename string
	SQL      string
	// Checksum is the lowercase hex SHA-256 of the file's bytes. It is recorded in
	// schema_migrations so a changed file is detected rather than silently skipped.
	Checksum string
}

// loadMigrations reads the embedded migration files, sorted by numeric prefix. The
// order is the numeric value, not the string, so 0002 always follows 0001 and a
// 0010 added later does not sort before 0002.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: could not read embedded migrations: %w", err)
	}

	var out []migration
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		version, label, err := parseMigrationName(name)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[version]; dup {
			return nil, fmt.Errorf("store: migrations %s and %s share version %d", other, name, version)
		}
		seen[version] = name

		body, err := fs.ReadFile(migrationFS, path.Join("migrations", name))
		if err != nil {
			return nil, fmt.Errorf("store: could not read migration %s: %w", name, err)
		}
		sum := sha256.Sum256(body)
		out = append(out, migration{
			Version:  version,
			Name:     label,
			Filename: name,
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	if len(out) == 0 {
		return nil, errors.New("store: no embedded migrations found")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// parseMigrationName splits "0001_init.sql" into version 1 and name "init".
func parseMigrationName(name string) (int64, string, error) {
	base := strings.TrimSuffix(name, ".sql")
	prefix, label, ok := strings.Cut(base, "_")
	if !ok {
		return 0, "", fmt.Errorf("store: migration %q must be named <version>_<name>.sql", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("store: migration %q does not start with a positive numeric version", name)
	}
	if label == "" {
		return 0, "", fmt.Errorf("store: migration %q has no name", name)
	}
	return version, label, nil
}

// embeddedVersions lists the versions this binary carries. /readyz compares it
// against schema_migrations.
func embeddedVersions() ([]int64, error) {
	migrations, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	versions := make([]int64, 0, len(migrations))
	for _, m := range migrations {
		versions = append(versions, m.Version)
	}
	return versions, nil
}

// grantsSQL returns the frozen role/grant block (docs/CONTRACTS.md §6).
//
// The block's `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` is written to resolve the
// owner at execution time from current_user, so the same text is correct whether it
// runs inside 0001 or is re-applied on a later boot. owner is checked only to catch
// an empty connection identity early.
func grantsSQL(owner string) (string, error) {
	if strings.TrimSpace(owner) == "" {
		return "", errors.New("store: cannot apply grants without a known owner role")
	}
	if strings.TrimSpace(grantsFile) == "" {
		return "", errors.New("store: embedded grants.sql is empty")
	}
	return grantsFile, nil
}

// Base is embedded by every slice store. It carries the pool and the config and
// nothing else, so a slice store cannot reach a peer's internals through it.
type Base struct {
	db *DB
	// pool is set instead of db when the Base was built from a pool the caller
	// already held (NewBaseFromPool). Pool() prefers db so the two cannot disagree.
	pool *pgxpool.Pool
}

// NewBase wraps db for a slice store.
func NewBase(db *DB) Base { return Base{db: db} }

// NewBaseFromPool wraps a pool that the caller already holds, which is how a read
// model is built over a pool owned by someone else (a test, or a caller that opened
// its own connection). Production uses NewBase so the store keeps the config and the
// readiness checks with the pool.
//
// The resulting Base has no *DB, so Config, Ping and MigrationsApplied report that no
// store is attached; Pool and InTx work normally.
func NewBaseFromPool(pool *pgxpool.Pool) Base {
	if pool == nil {
		return Base{}
	}
	return Base{pool: pool}
}

// DB returns the underlying store.
func (b Base) DB() *DB { return b.db }

// Pool returns the runtime pool for queries.
func (b Base) Pool() *pgxpool.Pool {
	if b.db != nil {
		return b.db.Pool()
	}
	return b.pool
}

// Ping answers SELECT 1 through the base.
func (b Base) Ping(ctx context.Context) error {
	if b.db == nil {
		return errors.New("store: base has no database")
	}
	return b.db.Ping(ctx)
}

// MigrationsApplied reports whether every embedded migration version is present.
func (b Base) MigrationsApplied(ctx context.Context) error {
	if b.db == nil {
		return errors.New("store: base has no database")
	}
	return b.db.MigrationsApplied(ctx)
}

// InTx runs fn in a transaction and commits it, or rolls it back on error or panic.
// The panic is re-raised after the rollback so the server's recover middleware still
// reports it; without the rollback a panic would hold locks until the connection is
// discarded.
func (b Base) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	if fn == nil {
		return errors.New("store: InTx needs a function")
	}
	pool := b.Pool()
	if pool == nil {
		return errors.New("store: base has no database pool")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: could not begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		// Roll back with a fresh context: the request context may already be
		// cancelled, and a rollback that does not run leaks the connection until
		// the pool recycles it.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), txTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: could not commit transaction: %w", err)
	}
	committed = true
	return nil
}

// WithConfig returns the configuration the store was opened with.
func (b Base) WithConfig() *config.Config {
	if b.db == nil {
		return nil
	}
	return b.db.Config()
}

// Querier is the narrow database surface shared by *pgxpool.Pool and pgx.Tx.
//
// It exists so a store call can run either inside or outside a transaction without
// the caller caring which. The audit append path needs it most: an event must be
// able to join the caller's transaction (audit.Writer.AppendTx) or open its own, and
// both cases reach the same query helpers.
//
// Both *pgxpool.Pool and pgx.Tx satisfy it as written, so it is a view, not an
// adapter. A slice that needs only reads may declare its own narrower interface; it
// must not declare a second general-purpose one.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Compile-time proof that the two types the slices actually pass satisfy Querier.
var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (pgx.Tx)(nil)
)
