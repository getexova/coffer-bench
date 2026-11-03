package authapi

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"log/slog"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/store"
	authstore "coffer/internal/store/auth"
)

// apiPrefix is the mount point of the whole API (SPEC §7.2). Every route this
// package registers is registered with the prefix, because router.go mounts the
// handlers on the root mux.
const apiPrefix = "/api/v1"

// CodePasswordChangeRequired is the machine-readable 403 code returned while a
// caller still has to change their password (SPEC §4 P1(a)).
//
// It is an addition to the frozen code table in docs/CONTRACTS.md §2, made on the
// explicit instruction of the engineering lead so that the CLI and the acceptance
// script can key off a stable string instead of matching prose. It needs an entry
// in docs/DECISIONS.md, which this slice does not own; it is flagged in the
// slice report. The status is still 403 and the envelope is unchanged, so a client
// that only knows the frozen table still sees `forbidden`'s status.

// CodePasswordChangeRequired is the machine-readable 403 code returned while a
// caller still has to change their password (SPEC §4 P1(a)).
//
// It is an addition to the frozen code table in docs/CONTRACTS.md §2, made on the
// explicit instruction of the engineering lead so that the CLI and the acceptance
// script can key off a stable string instead of matching prose. It needs an entry
// in docs/DECISIONS.md, which this slice does not own; it is flagged in the
// slice report. The status is still 403 and the envelope is unchanged, so a client
// that only knows the frozen table still sees `forbidden`'s status.
const CodePasswordChangeRequired = "password_change_required"

// DB is what this slice needs from the database: the three query methods plus the
// ability to open a transaction for the operations that must commit a business
// change and its audit event together.
//
// A *pgxpool.Pool satisfies it directly. Deps.DB is the frozen *store.DB, so conn()
// returns its Pool(); this interface exists so the slice can also be driven by a
// pgx.Tx in tests without a second code path.

// DB is what this slice needs from the database: the three query methods plus the
// ability to open a transaction for the operations that must commit a business
// change and its audit event together.
//
// A *pgxpool.Pool satisfies it directly. Deps.DB is the frozen *store.DB, so conn()
// returns its Pool(); this interface exists so the slice can also be driven by a
// pgx.Tx in tests without a second code path.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Deps is what the auth slice receives from the composition root. It holds only the
// frozen cross-slice surface; the slice gets no peer's package.

// Deps is what the auth slice receives from the composition root. It holds only the
// frozen cross-slice surface; the slice gets no peer's package.
type Deps struct {
	DB     *store.DB
	Audit  audit.Writer
	Config *config.Config
	Log    *slog.Logger
}

// conn returns the database handle: the runtime pool carried by the frozen
// *store.DB. It returns nil when no database was configured, which every handler
// treats as a 500 rather than as an open door.

// conn returns the database handle: the runtime pool carried by the frozen
// *store.DB. It returns nil when no database was configured, which every handler
// treats as a 500 rather than as an open door.
func (d Deps) conn() DB {
	if d.DB == nil {
		return nil
	}
	pool := d.DB.Pool()
	if pool == nil {
		return nil
	}
	return pool
}

// logger returns the logger, or the default one.

// logger returns the logger, or the default one.
func (d Deps) logger() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// writer returns the audit writer, or the no-op writer.

// writer returns the audit writer, or the no-op writer.
func (d Deps) writer() audit.Writer {
	if d.Audit != nil {
		return d.Audit
	}
	return audit.NopWriter()
}

// api bundles the dependencies with the in-process state this slice owns: the
// lockout and throttle tables. It is built once by Register so that the limits
// survive across requests and are not re-created per call.

// api bundles the dependencies with the in-process state this slice owns: the
// lockout and throttle tables. It is built once by Register so that the limits
// survive across requests and are not re-created per call.
type api struct {
	Deps
	limits *limiter
}

// NewAuthenticator returns the reqctx.Authenticator that middleware calls once per
// request. It is the only place a bearer token is turned into an actor.

// canWrite reports whether a grant level permits a write (SPEC §2.4). It is a pure
// predicate on the stored level, kept here so the rule has one home.
func canWrite(level string) bool {
	return level == authstore.LevelWriter
}

// Bootstrap creates the platform admin on first boot, and only then: if any user
// exists it does nothing. It is called after migrations and before the listener
// starts, and it is safe to call on every boot.
//
// The platform admin is the one account created with must_change_password = false:
// the operator supplies that password from their own environment, so nobody else
// chose it, and gating it would deadlock the first run of every automated flow.
// Every account whose password is supplied by a DIFFERENT principal — a member
// added by an admin, an owner created by the platform admin — is gated.
