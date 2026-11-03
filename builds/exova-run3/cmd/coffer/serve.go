package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"coffer/internal/api/authapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/httpapi"
	"coffer/internal/reqctx"
)

// cmdServe runs the Coffer server: `coffer serve`, with `coffer server` accepted
// as an alias so the container image and the CLI cannot drift apart on the
// spelling.
//
// The binary carries both the CLI of SPEC §7.1 and the server entrypoint, so
// scripts/build.sh produces one artifact and bin/coffer can back the compose
// stack. Configuration is environment-only (SPEC §5), so there are no flags to
// override it; internal/config.Load is the single place env is parsed.
func (c *cli) cmdServe(args []string) error {
	fs := newFlagSet("serve")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "serve"); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		// config.Load names the offending variable and never echoes a value.
		return fmt.Errorf("serve: %w", err)
	}

	// JSON lines to stdout, one per request (SPEC §5).
	log := slog.New(slog.NewJSONHandler(c.stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The server entrypoint is the composition root for the two things that must
	// happen before it listens, and leaving either nil is silently wrong:
	//
	//   - Bootstrap creates the platform admin from COFFER_BOOTSTRAP_ADMIN_* on a
	//     fresh install. Without it a clean stack has no users and no way in.
	//   - Authenticator resolves bearer tokens. Without it every presented
	//     credential is rejected, so a correct PAT would still get 401.
	//
	// Both come from the auth slice; httpapi only carries them.
	// The authenticator resolves bearer tokens against the runtime pool, and that
	// pool does not exist until httpapi has migrated and opened it. The bootstrap
	// hook is the one point where the wired Deps are visible before the router is
	// built, so the authenticator is constructed there and handed back through a
	// pointer the hook closes over.
	//
	// If bootstrap never runs, no authenticator is installed, and httpapi rejects
	// every credential rather than admitting one (its nil case is closed, not open).
	var (
		authenticator reqctx.Authenticator
		appender      audit.Writer
	)
	opts := httpapi.Options{
		// The real audit writer is built here rather than left to httpapi's
		// fallback. Without it httpapi installs audit.NopWriter(), which accepts
		// every event and discards it: the slices believe they recorded the
		// action, audit_events stays empty, and `audit verify` reports "valid"
		// because an empty chain verifies trivially. A server that cannot record
		// what happened must not serve traffic, so a construction failure below
		// fails the boot instead of degrading silently.
		AuditWriter: lazyWriter(func() audit.Writer { return appender }),
		Bootstrap: func(ctx context.Context, deps httpapi.Deps) error {
			writer, err := audit.NewAppender(deps.DB)
			if err != nil {
				return fmt.Errorf("could not build the audit writer: %w", err)
			}
			appender = writer

			authDeps := authapi.Deps{
				DB:     deps.DB,
				Audit:  writer,
				Config: deps.Config,
				Log:    deps.Log,
			}
			authenticator = authapi.NewAuthenticator(authDeps)
			return authapi.Bootstrap(ctx, authDeps)
		},
	}

	// httpapi copies Options before Bootstrap runs, so the authenticator is
	// installed as an indirection that resolves at request time to whatever the
	// bootstrap hook built.
	opts.Authenticator = lazyAuthenticator(func() reqctx.Authenticator { return authenticator })

	// ServeWithOptions blocks until shutdown: it owns SIGTERM/SIGINT and in-flight
	// draining, and never calls os.Exit, so the exit code stays here.
	if err := httpapi.ServeWithOptions(context.Background(), cfg, log, opts); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// lazyAuthenticator defers resolving the real authenticator until the first
// request, by which time the bootstrap hook has built it. A nil inner
// authenticator means "reject every credential", which is httpapi's own closed
// default and never an open door.
type lazyAuthenticator func() reqctx.Authenticator

func (l lazyAuthenticator) Authenticate(ctx context.Context, token string) (reqctx.Actor, error) {
	inner := l()
	if inner == nil {
		return reqctx.Actor{}, reqctx.ErrUnauthenticated
	}
	return inner.Authenticate(ctx, token)
}

// Resolve forwards to the inner resolver when it provides one, so the must-change flag
// reaches middleware.
//
// This matters: without it the wrapper hides reqctx.ActorResolver behind the plain
// Authenticator interface, middleware cannot read the flag, and it falls back to
// treating every user as gated — locking out users who have already changed their
// password. A wrapper that forwards one method of a two-method capability silently
// narrows it.
func (l lazyAuthenticator) Resolve(ctx context.Context, token string) (reqctx.Actor, bool, error) {
	inner := l()
	if inner == nil {
		return reqctx.Actor{}, false, reqctx.ErrUnauthenticated
	}
	if resolver, ok := inner.(reqctx.ActorResolver); ok {
		return resolver.Resolve(ctx, token)
	}
	actor, err := inner.Authenticate(ctx, token)
	if err != nil {
		return reqctx.Actor{}, false, err
	}
	// The inner authenticator cannot report the flag. Fail closed for a person and
	// leave a service token alone.
	return actor, actor.IsUser(), nil
}

// lazyWriter defers resolving the real audit writer until the first event, by
// which time the bootstrap hook has built it from the runtime pool.
//
// A nil inner writer is a hard error rather than a silent no-op: an event that
// cannot be recorded means the audit log is incomplete, and pretending the append
// succeeded is exactly the failure mode this indirection exists to prevent.
type lazyWriter func() audit.Writer

func (l lazyWriter) Append(ctx context.Context, e audit.Event) (audit.Event, error) {
	inner := l()
	if inner == nil {
		return audit.Event{}, errors.New("audit writer is not configured")
	}
	return inner.Append(ctx, e)
}

func (l lazyWriter) AppendTx(ctx context.Context, tx pgx.Tx, e audit.Event) (audit.Event, error) {
	inner := l()
	if inner == nil {
		return audit.Event{}, errors.New("audit writer is not configured")
	}
	return inner.AppendTx(ctx, tx, e)
}
