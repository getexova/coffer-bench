package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/crypto"
	"coffer/internal/reqctx"
	"coffer/internal/store"
)

// ShutdownBudget is how long in-flight requests get after SIGTERM before the server
// gives up and returns. SPEC §5 requires an exit within 10 s.
const ShutdownBudget = 10 * time.Second

// readHeaderTimeout bounds how long a client may take to send its headers.
const readHeaderTimeout = 10 * time.Second

// idleTimeout bounds a kept-alive connection with no request on it.
const idleTimeout = 60 * time.Second

// BootstrapFunc creates the platform admin when no users exist. The auth slice
// provides it; Serve calls it after migrations and before it starts listening, so a
// fresh install is reachable the moment /readyz is green.
//
// It must be idempotent: it runs on every boot.
type BootstrapFunc func(ctx context.Context, deps Deps) error

// Options are the optional wiring for Serve. The zero value is production behaviour.
type Options struct {
	// Bootstrap runs once after migrations. Nil means no bootstrap step.
	Bootstrap BootstrapFunc
	// Authenticator resolves bearer tokens. Nil means every presented credential is
	// rejected; it is never a bypass.
	Authenticator reqctx.Authenticator
	// AuditWriter is the audit log writer. It is required: ServeWithOptions refuses
	// to boot without one, because a server that cannot record audit events must
	// not serve traffic.
	AuditWriter audit.Writer
	// Handler overrides the built router. Tests use it; production leaves it nil.
	Handler http.Handler
}

// Serve runs the HTTP server until ctx is cancelled or SIGTERM/SIGINT arrives, then
// drains and returns. It blocks. A non-nil error means the server never became ready
// or could not listen; a nil error means a clean shutdown.
func Serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return ServeWithOptions(ctx, cfg, log, Options{})
}

// ServeWithOptions is Serve with explicit wiring.
func ServeWithOptions(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) error {
	if cfg == nil {
		return errors.New("httpapi: nil config")
	}
	if log == nil {
		log = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// A server with no audit writer does not start. This is checked before the
	// listener and before the database, because it is a wiring mistake, not a
	// runtime condition: an audit log that accepts every event and discards it
	// makes the server look healthy while recording nothing, and an empty chain
	// even verifies as valid.
	if opts.AuditWriter == nil {
		return errors.New("httpapi: no audit writer configured; refusing to serve without an audit log")
	}

	// Log the non-fatal configuration findings before doing any work, so a degraded
	// role is announced even if the database then fails to come up.
	for _, warning := range cfg.Warnings {
		log.Warn(warning)
	}

	// The listener is opened before migrations so a port conflict fails fast,
	// instead of after a migration run the operator then has to reason about.
	listenAddr := cfg.Addr()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("httpapi: could not listen on %s: %w", listenAddr, err)
	}

	// The effective address, which differs from the configured one when the port is
	// 0, and the WARN when the API is reachable from off-host without a proxy.
	effective := listener.Addr().String()
	log.Info("listening", "addr", effective, "env", cfg.Env)
	if !cfg.IsLoopback() {
		log.Warn("binding to a non-loopback address: the API is plaintext HTTP and must sit behind a TLS-terminating reverse proxy",
			"addr", effective)
	}

	// The database: migrate as the owner, then open the runtime pool.
	db, err := store.Boot(ctx, cfg, log)
	if err != nil {
		_ = listener.Close()
		return err
	}
	defer db.Close()

	deps := Deps{DB: db, Audit: opts.AuditWriter, Config: cfg, Log: log}

	// Master-key rotation runs before anything can report ready (SPEC §4).
	//
	// With COFFER_MASTER_KEY_PREVIOUS set, every project data key is re-wrapped
	// under the current master key here. Once this returns nil the old key is no
	// longer needed and can be removed from the environment. Without this call the
	// process starts happily and every stored value fails to decrypt, because the
	// data keys are still wrapped under the retired key.
	//
	// A failure is fatal rather than a warning: serving traffic with keys wrapped
	// under a key the operator believes they have retired means every read is a 500,
	// and the operator would have no signal that the rotation did not happen.
	if len(cfg.MasterKeyPrevious) > 0 {
		newSealer, err := crypto.NewSealerFromBytes(cfg.MasterKey)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("httpapi: master key: %w", err)
		}
		oldSealer, err := crypto.NewSealerFromBytes(cfg.MasterKeyPrevious)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("httpapi: previous master key: %w", err)
		}
		rotated, err := crypto.RotateIfNeededCount(ctx, db.Pool(), oldSealer.Master(), newSealer.Master())
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("httpapi: master key rotation failed: %w", err)
		}
		// The count and neither key are logged: the keys must never reach a log.
		log.Info("master key rotated", "data_keys_rewrapped", rotated)
	}

	if opts.Bootstrap != nil {
		bootstrapCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := opts.Bootstrap(bootstrapCtx, deps)
		cancel()
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("httpapi: bootstrap failed: %w", err)
		}
		log.Info("bootstrap complete")
	}

	handler := opts.Handler
	if handler == nil {
		handler = NewRouter(deps, opts.Authenticator)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		// No WriteTimeout: an export of 1,000 secrets can legitimately take longer
		// than a fixed budget, and a truncated body is worse than a slow one. The
		// per-request work is bounded by the store timeouts.
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// Stop accepting on SIGTERM/SIGINT, or when the caller cancels.
	signalCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()

	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	log.Info("server ready")

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("httpapi: serve failed: %w", err)
		}
		return nil
	case <-signalCtx.Done():
	}

	// Distinguish "the operator asked us to stop" from "the context was cancelled
	// because something upstream failed". Either way the drain is the same.
	log.Info("shutting down", "budget_s", ShutdownBudget.Seconds())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownBudget)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		// The budget expired with requests still in flight. Close what is left and
		// report it, rather than hanging past the 10 s SPEC §5 allows.
		log.Warn("shutdown budget expired; closing remaining connections", "error", err.Error())
		if closeErr := server.Close(); closeErr != nil {
			log.Warn("could not close the server", "error", closeErr.Error())
		}
		if err := <-serveErr; err != nil {
			return fmt.Errorf("httpapi: serve failed during shutdown: %w", err)
		}
		return nil
	}

	if err := <-serveErr; err != nil {
		return fmt.Errorf("httpapi: serve failed during shutdown: %w", err)
	}

	log.Info("stopped")
	return nil
}
