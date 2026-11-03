// Package app wires configuration, database, and the HTTP API together and
// runs the boot sequence (CONTRACT §4).
package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/coffer-dev/coffer/internal/server/api"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
	"github.com/coffer-dev/coffer/internal/server/db"
)

// App is one Coffer server instance.
type App struct {
	Cfg   *config.Config
	Log   *slog.Logger
	API   *api.Server
	pool  *pgxpool.Pool
	owner *pgxpool.Pool
}

// NewLogger returns the JSON-lines logger used for request logs and
// operational messages ({"ts","level","msg",...}).
func NewLogger(w *os.File) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 {
				switch a.Key {
				case slog.TimeKey:
					return slog.String("ts", a.Value.Time().UTC().Format("2006-01-02T15:04:05.000000Z"))
				case slog.LevelKey:
					return slog.String("level", strings.ToLower(a.Value.String()))
				}
			}
			return a
		},
	}))
}

// New builds an App; the API answers /healthz immediately.
func New(cfg *config.Config, log *slog.Logger) *App {
	h := crypto.NewHasher(cfg.Argon2MemoryKiB)
	return &App{Cfg: cfg, Log: log, API: api.New(cfg, log, h)}
}

// ErrFatal wraps boot errors after which the process must exit 1.
type ErrFatal struct{ Err error }

func (e *ErrFatal) Error() string { return e.Err.Error() }
func (e *ErrFatal) Unwrap() error { return e.Err }

// Boot runs steps 3–7 of the boot sequence. It retries the DB connection
// until ctx ends. Errors are fatal.
func (a *App) Boot(ctx context.Context) error {
	owner, err := db.Connect(ctx, a.Cfg.DatabaseURL, 4, a.Log)
	if err != nil {
		return err
	}
	a.owner = owner
	if err := retry(ctx, a.Log, "migrations", func() error { return db.Migrate(ctx, owner) }); err != nil {
		return &ErrFatal{err}
	}
	a.Log.Info("migrations applied")

	// The master-key check runs before anything that changes the deployment
	// (app role password, grants), so a refused boot leaves a running server
	// untouched (SPEC §4 Startup check).
	canary, err := db.CheckMasterKey(ctx, owner, a.Cfg.MasterKey, a.Cfg.PreviousMasterKey, a.Log)
	if err != nil {
		if errors.Is(err, db.ErrMasterKeyMismatch) {
			return &ErrFatal{err}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &ErrFatal{errors.New("master key check failed: " + firstLine(err))}
	}

	// P1: restricted app role. Any failure falls back to the owner pool.
	var pool *pgxpool.Pool
	appCfg, err := db.SetupAppRole(ctx, owner, a.Cfg.DatabaseURL, a.Cfg.AppRole, canary)
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		pool, err = db.ConnectConfig(cctx, appCfg, 25, nil)
		cancel()
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.Log.Warn("restricted app role unavailable; using the owner connection", "error", firstLine(err))
		cfg, perr := pgxpool.ParseConfig(a.Cfg.DatabaseURL)
		if perr != nil {
			return &ErrFatal{perr}
		}
		pool, err = db.ConnectConfig(ctx, cfg, 25, a.Log)
		if err != nil {
			return err
		}
	} else {
		a.Log.Info("using restricted database role", "role", a.Cfg.AppRole)
	}
	a.pool = pool

	hash, err := crypto.NewHasher(a.Cfg.Argon2MemoryKiB).Hash(ctx, a.Cfg.BootstrapPassword)
	if err != nil {
		return err
	}
	created, err := db.Bootstrap(ctx, owner, a.Cfg.BootstrapEmail, hash)
	if err != nil {
		return &ErrFatal{errors.New("bootstrap failed: " + firstLine(err))}
	}
	if created {
		a.Log.Info("platform admin created")
	}
	owner.Close()
	a.owner = nil
	a.API.SetReady(pool)
	a.Log.Info("ready")
	return nil
}

func retry(ctx context.Context, log *slog.Logger, what string, f func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = f(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn(what+" failed, retrying", "error", firstLine(err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return err
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// Close releases resources (after the HTTP server has shut down).
func (a *App) Close() {
	a.API.Close()
	if a.pool != nil {
		a.pool.Close()
	}
	if a.owner != nil {
		a.owner.Close()
	}
}

// HTTPServer returns an http.Server with the contract's timeouts.
func (a *App) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           a.API,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		// Let "OPTIONS *" reach our handler (JSON 404 with the standard
		// headers and a request log line) instead of net/http's bare 200.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn),
	}
}

// Run validates nothing (cfg is already valid): it listens, boots, and
// serves until ctx is cancelled, then shuts down gracefully. It returns the
// process exit code.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) int {
	a := New(cfg, log)
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listen failed", "addr", cfg.ListenAddr, "error", err.Error())
		return 1
	}
	srv := a.HTTPServer()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String())

	bootCtx, cancelBoot := context.WithCancel(ctx)
	defer cancelBoot()
	bootErr := make(chan error, 1)
	go func() { bootErr <- a.Boot(bootCtx) }()

	code := 0
	bootDone := false
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		log.Error("http server failed", "error", err.Error())
		code = 1
	case err := <-bootErr:
		bootDone = true
		if err != nil {
			if ctx.Err() == nil {
				log.Error(firstLine(err))
				code = 1
			}
		} else {
			select {
			case <-ctx.Done():
			case err := <-serveErr:
				log.Error("http server failed", "error", err.Error())
				code = 1
			}
		}
	}
	cancelBoot()
	if !bootDone {
		<-bootErr // Boot honours ctx; wait so Close does not race it.
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("graceful shutdown incomplete", "error", err.Error())
	}
	a.Close()
	log.Info("stopped")
	return code
}

// PoolUser reports the database role used by the request pool ("" before boot).
func (a *App) PoolUser() string {
	if a.pool == nil {
		return ""
	}
	return a.pool.Config().ConnConfig.User
}
