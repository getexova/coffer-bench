// Package config loads Coffer's process configuration from the environment.
//
// Configuration comes from environment variables only (docs/CONTRACTS.md §10).
// The values live in files — `.env` for development and review, `.env.production`
// for production, `.env.example` as the committed key-names-only template — and it
// is the container runtime or the process supervisor that turns those files into
// the process environment. The binary itself never reads a dotenv file, so a value
// that exists only in an interactive shell is not configuration and will not be
// seen by CI or by the next clone.
//
// Every secret this package accepts is validated here and nowhere else: the master
// key must decode to exactly 32 bytes and must not be the shipped placeholder, the
// bootstrap password must be at least 12 characters, and the database role must be
// resolved by the gated rules in docs/CONTRACTS.md §11. No value is ever echoed in
// an error message.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Environment names accepted by COFFER_ENV.
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// Defaults for optional variables (docs/CONTRACTS.md §10).
const (
	DefaultPort      = 8420
	DefaultBindAddr  = "127.0.0.1"
	DefaultDBHost    = "127.0.0.1"
	DefaultDBPort    = 5432
	DefaultDBSSLMode = "disable"
)

// MasterKeyLen is the exact decoded length of COFFER_MASTER_KEY.
const MasterKeyLen = 32

// MinBootstrapPasswordLen is the minimum length of the bootstrap admin password.
const MinBootstrapPasswordLen = 12

// AppDBRole is the unprivileged runtime role created by migration 0001.
const AppDBRole = "coffer_app"

// PlaceholderMasterKey is the literal COFFER_MASTER_KEY that ships in
// `.env.example`. The server refuses to start with this value, because a copy of
// the example file must never become a working installation.
const PlaceholderMasterKey = "REPLACE_WITH_OPENSSL_RAND_BASE64_32"

// placeholderMarkers are substrings that mark a value as an unfilled template.
// They are checked case-insensitively against the raw variable, so an
// `.env.example` that drifts from PlaceholderMasterKey is still refused.
var placeholderMarkers = []string{
	"placeholder",
	"replace_with",
	"replace-with",
	"replaceme",
	"changeme",
	"change_me",
	"change-me",
	"yourkey",
	"your_key",
	"your-key",
	"xxxxxxxx",
}

// RoleMode records which database role the runtime pool authenticates as.
type RoleMode string

const (
	// RoleApp is the normal mode: the runtime pool is the unprivileged
	// coffer_app role, which owns nothing and cannot rewrite the audit log.
	RoleApp RoleMode = "app"

	// RoleOwnerDegraded is the explicitly opted-in single-role mode. The
	// runtime pool is the owner role, so the isolation coffer_app exists to
	// provide is gone. Only reachable outside production with
	// COFFER_ALLOW_DEGRADED_DB_ROLE=1.
	RoleOwnerDegraded RoleMode = "owner-degraded"
)

// MissingEnvError names a required variable that was not set. main prints it and
// exits non-zero, so the operator learns which variable to provide.
type MissingEnvError struct {
	Name string
}

func (e *MissingEnvError) Error() string {
	return "missing required environment variable " + e.Name
}

// Config is the fully validated process configuration.
type Config struct {
	// MasterKey is the 32-byte key-encryption key for envelope encryption.
	MasterKey []byte
	// MasterKeyPrevious is set only during a rotation and is never persisted.
	MasterKeyPrevious []byte

	BootstrapAdminEmail    string
	BootstrapAdminPassword string

	Port     int
	BindAddr string
	Env      string

	// TrustProxy enables the rightmost-untrusted X-Forwarded-For resolver
	// (docs/CONTRACTS.md §8).
	TrustProxy bool

	DB Database

	// Warnings are non-fatal findings that main logs at startup. They never
	// carry a secret value.
	Warnings []string
}

// Database is the resolved database configuration: the owner connection used for
// migrations, the runtime connection used for serving, and the role mode.
type Database struct {
	Host      string
	Port      int
	SSLMode   string
	Database  string
	OwnerUser string

	// AppPassword is empty in degraded mode and is never logged.
	AppPassword   string
	AllowDegraded bool

	// MaxConns and MinConns size the runtime pool. Zero means "use the default".
	MaxConns int32
	MinConns int32
	Mode     RoleMode

	migrationURL string
	runtimeURL   string
}

// Pool sizing defaults, mirrored from internal/store so an operator reading
// .env.example and the code sees one number. Duplicated rather than imported to keep
// internal/config free of a database dependency.
const (
	DefaultMaxConns = int32(32)
	DefaultMinConns = int32(4)
)

// DBMaxConns is the runtime pool ceiling.
func (c *Config) DBMaxConns() int32 {
	if c == nil || c.DB.MaxConns <= 0 {
		return DefaultMaxConns
	}
	return c.DB.MaxConns
}

// DBMinConns is the runtime pool's warm floor.
func (c *Config) DBMinConns() int32 {
	if c == nil || c.DB.MinConns <= 0 {
		return DefaultMinConns
	}
	return c.DB.MinConns
}

// MigrationURL is the owner connection string used to apply migrations. It is
// never handed to the runtime pool.
func (c *Config) MigrationURL() string { return c.DB.migrationURL }

// RuntimeURL is the connection string for the serving pool. In degraded mode it
// is the owner connection string.
func (c *Config) RuntimeURL() string { return c.DB.runtimeURL }

// Degraded reports whether the runtime pool runs as the owner role.
func (c *Config) Degraded() bool { return c.DB.Mode == RoleOwnerDegraded }

// IsProduction reports whether the server runs with production safeguards.
func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

// Addr is the listen address as host:port.
func (c *Config) Addr() string { return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port)) }

// IsLoopback reports whether the bind address is a loopback address. server.go
// logs a WARN when it is not, because the API is plaintext HTTP and expects a
// reverse proxy in front.
func (c *Config) IsLoopback() bool {
	if strings.EqualFold(c.BindAddr, "localhost") {
		return true
	}
	ip := net.ParseIP(c.BindAddr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// Load reads and validates the configuration from the process environment.
func Load() (*Config, error) {
	return LoadFrom(os.LookupEnv)
}

// LoadFrom reads and validates the configuration from lookup. Tests use it with a
// map-backed lookup so they never mutate the process environment.
func LoadFrom(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		return nil, errors.New("config: nil lookup")
	}

	cfg := &Config{}

	rawKey, err := required(lookup, "COFFER_MASTER_KEY")
	if err != nil {
		return nil, err
	}
	cfg.MasterKey, err = decodeMasterKey("COFFER_MASTER_KEY", rawKey)
	if err != nil {
		return nil, err
	}

	if raw, ok := lookup("COFFER_MASTER_KEY_PREVIOUS"); ok && strings.TrimSpace(raw) != "" {
		cfg.MasterKeyPrevious, err = decodeMasterKey("COFFER_MASTER_KEY_PREVIOUS", raw)
		if err != nil {
			return nil, err
		}
		if string(cfg.MasterKeyPrevious) == string(cfg.MasterKey) {
			return nil, errors.New("COFFER_MASTER_KEY_PREVIOUS equals COFFER_MASTER_KEY; unset it when no rotation is in progress")
		}
	}

	if cfg.BootstrapAdminEmail, err = required(lookup, "COFFER_BOOTSTRAP_ADMIN_EMAIL"); err != nil {
		return nil, err
	}
	cfg.BootstrapAdminEmail = strings.ToLower(strings.TrimSpace(cfg.BootstrapAdminEmail))
	if !strings.Contains(cfg.BootstrapAdminEmail, "@") {
		return nil, errors.New("COFFER_BOOTSTRAP_ADMIN_EMAIL is not an email address")
	}

	if cfg.BootstrapAdminPassword, err = required(lookup, "COFFER_BOOTSTRAP_ADMIN_PASSWORD"); err != nil {
		return nil, err
	}
	if n := utf8.RuneCountInString(cfg.BootstrapAdminPassword); n < MinBootstrapPasswordLen {
		return nil, fmt.Errorf("COFFER_BOOTSTRAP_ADMIN_PASSWORD must be at least %d characters, got %d", MinBootstrapPasswordLen, n)
	}

	cfg.Port, err = intVar(lookup, "COFFER_PORT", DefaultPort, 1, 65535)
	if err != nil {
		return nil, err
	}
	cfg.BindAddr = stringVar(lookup, "COFFER_BIND_ADDR", DefaultBindAddr)
	if net.ParseIP(cfg.BindAddr) == nil && !strings.EqualFold(cfg.BindAddr, "localhost") {
		return nil, fmt.Errorf("COFFER_BIND_ADDR is not an IP address or localhost: %q", cfg.BindAddr)
	}

	cfg.Env = strings.ToLower(stringVar(lookup, "COFFER_ENV", EnvProduction))
	switch cfg.Env {
	case EnvProduction, EnvDevelopment:
	default:
		return nil, fmt.Errorf("COFFER_ENV must be %q or %q, got %q", EnvProduction, EnvDevelopment, cfg.Env)
	}

	cfg.TrustProxy = boolVar(lookup, "COFFER_TRUST_PROXY")

	if err := loadDatabase(lookup, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadDatabase resolves the migration and runtime connection strings and applies
// the degraded-role gate from docs/CONTRACTS.md §11.
func loadDatabase(lookup func(string) (string, bool), cfg *Config) error {
	db := &cfg.DB

	var err error
	if db.Host = stringVar(lookup, "COFFER_DB_HOST", DefaultDBHost); db.Host == "" {
		return errors.New("COFFER_DB_HOST must not be empty")
	}
	if db.Port, err = intVar(lookup, "COFFER_DB_PORT", DefaultDBPort, 1, 65535); err != nil {
		return err
	}
	if db.SSLMode = stringVar(lookup, "COFFER_DB_SSLMODE", DefaultDBSSLMode); db.SSLMode == "" {
		return errors.New("COFFER_DB_SSLMODE must not be empty")
	}
	switch db.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("COFFER_DB_SSLMODE must be one of disable|allow|prefer|require|verify-ca|verify-full, got %q", db.SSLMode)
	}

	// Pool sizing. Bounded on purpose: PostgreSQL's max_connections defaults to 100,
	// and an unbounded pool turns a load spike into "too many clients already".
	if raw := strings.TrimSpace(stringVar(lookup, "COFFER_DB_MAX_CONNS", "")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			return fmt.Errorf("COFFER_DB_MAX_CONNS must be an integer between 1 and 500, got %q", raw)
		}
		db.MaxConns = int32(n)
	}
	if raw := strings.TrimSpace(stringVar(lookup, "COFFER_DB_MIN_CONNS", "")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 500 {
			return fmt.Errorf("COFFER_DB_MIN_CONNS must be an integer between 0 and 500, got %q", raw)
		}
		db.MinConns = int32(n)
	}

	db.AllowDegraded = boolVar(lookup, "COFFER_ALLOW_DEGRADED_DB_ROLE")
	db.AppPassword = strings.TrimSpace(stringVar(lookup, "COFFER_APP_DB_PASSWORD", ""))

	// The runtime role. This is the §11 gate; a rejected credential is handled at
	// connect time in internal/store and is always a failed start.
	switch {
	case db.AppPassword != "":
		db.Mode = RoleApp
		if db.AllowDegraded {
			cfg.Warnings = append(cfg.Warnings,
				"COFFER_ALLOW_DEGRADED_DB_ROLE is set but COFFER_APP_DB_PASSWORD is present; running as "+AppDBRole+" and ignoring the degraded flag")
		}
	case db.AllowDegraded && cfg.IsProduction():
		return fmt.Errorf("refusing to start: COFFER_ALLOW_DEGRADED_DB_ROLE is set with COFFER_ENV=%s; set COFFER_APP_DB_PASSWORD to the %s role password and unset COFFER_ALLOW_DEGRADED_DB_ROLE", cfg.Env, AppDBRole)
	case db.AllowDegraded:
		db.Mode = RoleOwnerDegraded
		cfg.Warnings = append(cfg.Warnings,
			"running as the database owner role because COFFER_APP_DB_PASSWORD is unset and COFFER_ALLOW_DEGRADED_DB_ROLE=1: the "+AppDBRole+" isolation is lost, so the server can DDL and can rewrite the audit log")
	default:
		return fmt.Errorf("COFFER_APP_DB_PASSWORD is not set: set it to the %s role password, or set COFFER_ALLOW_DEGRADED_DB_ROLE=1 outside production to run as the owner role", AppDBRole)
	}

	// Migration connection: explicit override, else derived from the owner role.
	if raw := strings.TrimSpace(stringVar(lookup, "COFFER_MIGRATION_DATABASE_URL", "")); raw != "" {
		if err := validateURL("COFFER_MIGRATION_DATABASE_URL", raw); err != nil {
			return err
		}
		db.migrationURL = raw
		if err := fillDatabaseName(raw, db); err != nil {
			return err
		}
	} else {
		if db.OwnerUser, err = required(lookup, "POSTGRES_USER"); err != nil {
			return err
		}
		ownerPassword, err := required(lookup, "POSTGRES_PASSWORD")
		if err != nil {
			return err
		}
		if db.Database, err = required(lookup, "POSTGRES_DB"); err != nil {
			return err
		}
		db.migrationURL = buildURL(db.OwnerUser, ownerPassword, db)
	}

	// Runtime connection: explicit override, else coffer_app, else (degraded) the
	// owner connection.
	if raw := strings.TrimSpace(stringVar(lookup, "DATABASE_URL", "")); raw != "" {
		if err := validateURL("DATABASE_URL", raw); err != nil {
			return err
		}
		db.runtimeURL = raw
		return fillDatabaseName(raw, db)
	}
	if db.Database == "" {
		var err error
		if db.Database, err = required(lookup, "POSTGRES_DB"); err != nil {
			return err
		}
	}
	switch db.Mode {
	case RoleApp:
		db.runtimeURL = buildURL(AppDBRole, db.AppPassword, db)
	default:
		db.runtimeURL = db.migrationURL
	}
	return nil
}

// buildURL assembles a postgres URL, escaping the password so that a password
// containing '@', '/', ':' or '?' cannot corrupt the connection string.
func buildURL(user, password string, db *Database) string {
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(db.Host, strconv.Itoa(db.Port)),
		Path:     "/" + db.Database,
		RawQuery: "sslmode=" + url.QueryEscape(db.SSLMode),
	}
	return u.String()
}

func validateURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %v", name, err)
	}
	switch u.Scheme {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("%s must use the postgres:// scheme, got %q", name, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host", name)
	}
	return nil
}

// fillDatabaseName records the database name of an explicit URL so the rest of the
// configuration has a consistent view. It never overrides an explicit POSTGRES_DB.
func fillDatabaseName(raw string, db *Database) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("database URL is not a valid URL: %v", err)
	}
	if db.Database == "" {
		db.Database = strings.TrimPrefix(u.Path, "/")
	}
	return nil
}

// decodeMasterKey validates a base64 master key without ever echoing it.
func decodeMasterKey(name, raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, &MissingEnvError{Name: name}
	}
	if raw == PlaceholderMasterKey || looksLikePlaceholder(raw) {
		return nil, fmt.Errorf("%s is the placeholder value from .env.example; generate a real key with `openssl rand -base64 32`", name)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if key, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			return nil, fmt.Errorf("%s is not valid base64", name)
		}
	}
	if len(key) != MasterKeyLen {
		return nil, fmt.Errorf("%s must decode to exactly %d bytes, got %d", name, MasterKeyLen, len(key))
	}
	return key, nil
}

func looksLikePlaceholder(raw string) bool {
	lower := strings.ToLower(raw)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func required(lookup func(string) (string, bool), name string) (string, error) {
	raw, ok := lookup(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return "", &MissingEnvError{Name: name}
	}
	return strings.TrimSpace(raw), nil
}

func stringVar(lookup func(string) (string, bool), name, def string) string {
	raw, ok := lookup(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	return strings.TrimSpace(raw)
}

func intVar(lookup func(string) (string, bool), name string, def, min, max int) (int, error) {
	raw, ok := lookup(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", name, raw)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d, got %d", name, min, max, n)
	}
	return n, nil
}

// boolVar reads a flag. "1" is the documented form; "true" is accepted because a
// compose file written by hand reaches for it, and refusing it would be a
// surprising way to lose a security setting.
func boolVar(lookup func(string) (string, bool), name string) bool {
	raw, ok := lookup(name)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
