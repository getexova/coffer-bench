// Package authstore is the store layer for organizations, users, members, grants,
// projects, environments and tokens.
//
// Every store package embeds store.Base, which supplies the pool and a transaction
// helper, so a store function here takes a Querier and therefore runs unchanged on
// the runtime pool or inside a caller's open transaction.
//
// Rules that hold for every query in this package:
//   - The organization comes from the authenticated actor, never from a request
//     field, so a caller cannot address another tenant.
//   - Revocation is read on every request with no cache anywhere
//     (docs/CONTRACTS.md §8).
//   - A password, token or secret value never appears in an error string.
package authstore

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the narrow query surface both a *pgxpool.Pool and a pgx.Tx satisfy.
//
// It is declared in this package rather than imported from internal/store so the
// slice keeps its own seam: the secrets slice declares an identical
// secretsstore.Querier, and neither reaches into the other. A single shared
// Querier in internal/store would be equivalent; this one exists so the slice
// compiles and is testable on its own.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DB is a Querier that can also open a transaction. A *pgxpool.Pool satisfies it
// directly, which is what the API layer holds.
type DB interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// pgxRow and pgxRows are local aliases so one scanner serves both QueryRow and
// Query results: pgx.Rows satisfies pgx.Row.
type (
	pgxRow  = pgx.Row
	pgxRows = pgx.Rows
)

var (
	// ErrNotFound means the row does not exist, or is invisible under the
	// caller's predicate. Callers translate it to 404 and must never
	// distinguish the two cases.
	ErrNotFound = errors.New("authstore: not found")

	// ErrConflict means a unique constraint was violated: a duplicate email, or
	// a duplicate slug inside one organization.
	ErrConflict = errors.New("authstore: conflict")
)

// mapErr translates driver errors into this package's sentinels. Everything
// else is returned untouched so the API layer can log it as an internal error.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

// NormalizeEmail lowercases and trims an address. Addresses are stored and
// looked up in this form only.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// collect runs a row scanner over every row and returns a non-nil slice, so a
// JSON encoder emits [] rather than null for an empty result.
func collect[T any](rows pgx.Rows, scan func(pgx.Rows) (T, error)) ([]T, error) {
	defer rows.Close()
	out := make([]T, 0, 8)
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}
