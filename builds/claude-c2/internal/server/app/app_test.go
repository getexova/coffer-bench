package app_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/coffer-dev/coffer/internal/server/app"
	"github.com/coffer-dev/coffer/internal/server/db"
	"github.com/coffer-dev/coffer/internal/server/testutil"
)

const pw = "correct-horse-battery"

func bootErr(t *testing.T, d *testutil.DB, key, prev []byte) error {
	cfg := d.Config(key)
	cfg.PreviousMasterKey = prev
	a := app.New(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := a.Boot(ctx)
	a.Close()
	return err
}

func seed(t *testing.T, s *testutil.Server) *testutil.Client {
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	pa.Must(t, 201, "POST", "/admin/orgs", map[string]string{"slug": "org", "owner_email": "o@org.test", "owner_password": pw})
	o := s.Client(s.Login(t, "o@org.test", pw))
	o.Must(t, 201, "POST", "/projects", map[string]string{"slug": "app"})
	o.Must(t, 201, "POST", "/projects", map[string]string{"slug": "app2"})
	o.Must(t, 201, "POST", "/projects/app/envs", map[string]any{"slug": "dev"})
	o.Must(t, 201, "POST", "/projects/app2/envs", map[string]any{"slug": "dev"})
	o.Must(t, 200, "PUT", "/projects/app/envs/dev/secrets/K", map[string]string{"value": "v1"})
	o.Must(t, 200, "PUT", "/projects/app2/envs/dev/secrets/K", map[string]string{"value": "v2"})
	return o
}

func TestRebootIdempotentAndRotation(t *testing.T) {
	d := testutil.NewDB(t)
	k1, k2, k3 := testutil.RandomKeyBytes(), testutil.RandomKeyBytes(), testutil.RandomKeyBytes()
	s1 := testutil.Boot(t, d, d.Config(k1))
	if s1.App.PoolUser() != d.Role {
		t.Errorf("pool user %q, want restricted role %q", s1.App.PoolUser(), d.Role)
	}
	seed(t, s1)
	s1.HTTP.Close()
	s1.App.Close()

	// Second boot with the same key: migrations idempotent, bootstrap skipped,
	// grants re-applied.
	s2 := testutil.Boot(t, d, d.Config(k1))
	o := s2.Client(s2.Login(t, "o@org.test", pw))
	o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets/K", nil)
	var admins int
	d.Owner.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE role='platform_admin'`).Scan(&admins)
	if admins != 1 {
		t.Fatalf("platform admins %d", admins)
	}
	s2.HTTP.Close()
	s2.App.Close()

	// Wrong key: refuse.
	if err := bootErr(t, d, k2, nil); !errors.Is(err, db.ErrMasterKeyMismatch) {
		t.Fatalf("wrong key boot: %v", err)
	}
	// Wrong previous key: refuse.
	if err := bootErr(t, d, k2, k3); !errors.Is(err, db.ErrMasterKeyMismatch) {
		t.Fatalf("wrong previous key boot: %v", err)
	}
	// Rotation k1 -> k2.
	rot := d.Config(k2)
	rot.PreviousMasterKey = k1
	s3 := testutil.Boot(t, d, rot)
	s3.HTTP.Close()
	s3.App.Close()
	// After rotation the old key is not needed, and no longer works.
	s4 := testutil.Boot(t, d, d.Config(k2))
	o = s4.Client(s4.Login(t, "o@org.test", pw))
	for _, p := range []string{"app", "app2"} {
		v := o.Must(t, 200, "GET", "/projects/"+p+"/envs/dev/secrets/K", nil).Map(t)["value"]
		if v != "v1" && v != "v2" {
			t.Fatalf("after rotation: %v", v)
		}
	}
	if o.Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"] != true {
		t.Fatal("chain invalid after rotation")
	}
	s4.HTTP.Close()
	s4.App.Close()
	if err := bootErr(t, d, k1, nil); !errors.Is(err, db.ErrMasterKeyMismatch) {
		t.Fatalf("old key still accepted: %v", err)
	}
	// Rotation again with the same pair is idempotent.
	if err := bootErr(t, d, k2, k1); err != nil {
		t.Fatalf("repeat rotation: %v", err)
	}
}

func TestAppRoleCannotTamperAudit(t *testing.T) {
	d := testutil.NewDB(t)
	s := testutil.Boot(t, d, nil)
	seed(t, s)
	ctx := t.Context()
	tx, err := d.Owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+d.Role); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE audit_events SET target='x'`, `DELETE FROM audit_events`, `TRUNCATE audit_events`} {
		if _, err := tx.Exec(ctx, `SAVEPOINT sp`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, q)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s as app role: %v (want permission denied)", q, err)
		}
		tx.Exec(ctx, `ROLLBACK TO SAVEPOINT sp`)
	}
	// The app role can still read and insert.
	if _, err := tx.Exec(ctx, `SELECT count(*) FROM audit_events`); err != nil {
		t.Errorf("select: %v", err)
	}
	tx.Rollback(ctx)
	// The owner is stopped by the trigger.
	if _, err := d.Owner.Exec(ctx, `UPDATE audit_events SET target='x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("owner update: %v", err)
	}
	if _, err := d.Owner.Exec(ctx, `DELETE FROM audit_events`); err == nil {
		t.Error("owner delete succeeded")
	}
}

func TestAuditTamperDetected(t *testing.T) {
	d := testutil.NewDB(t)
	s := testutil.Boot(t, d, nil)
	o := seed(t, s)
	for i := 0; i < 5; i++ {
		o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets/K", nil)
	}
	if v := o.Must(t, 200, "GET", "/audit/verify", nil).Map(t); v["valid"] != true || v["first_invalid_seq"] != nil {
		t.Fatalf("baseline %v", v)
	}
	ctx := t.Context()
	exec := func(q string) {
		t.Helper()
		if _, err := d.Owner.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`DROP TRIGGER audit_events_immutable ON audit_events`)
	var chain string
	d.Owner.QueryRow(ctx, `SELECT id FROM orgs WHERE slug='org'`).Scan(&chain)
	verify := func() map[string]any { return o.Must(t, 200, "GET", "/audit/verify", nil).Map(t) }

	exec(`UPDATE audit_events SET target='tampered' WHERE chain='` + chain + `' AND seq=4`)
	if v := verify(); v["valid"] != false || v["first_invalid_seq"].(float64) != 4 {
		t.Fatalf("modified row: %v", v)
	}
	exec(`UPDATE audit_events SET details='{"version": 99}' WHERE chain='` + chain + `' AND seq=3`)
	if v := verify(); v["first_invalid_seq"].(float64) != 3 {
		t.Fatalf("modified details: %v", v)
	}
	exec(`DELETE FROM audit_events WHERE chain='` + chain + `' AND seq=2`)
	if v := verify(); v["first_invalid_seq"].(float64) != 2 {
		t.Fatalf("deleted row: %v", v)
	}
	// Platform chain unaffected.
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	if v := pa.Must(t, 200, "GET", "/admin/audit/verify", nil).Map(t); v["valid"] != true {
		t.Fatalf("platform chain %v", v)
	}
	// Truncating the tail is detected via the chain head.
	var last int64
	d.Owner.QueryRow(ctx, `SELECT max(seq) FROM audit_events WHERE chain='platform'`).Scan(&last)
	exec(`DELETE FROM audit_events WHERE chain='platform' AND seq=(SELECT max(seq) FROM audit_events WHERE chain='platform')`)
	v := pa.Must(t, 200, "GET", "/admin/audit/verify", nil).Map(t)
	if v["valid"] != false {
		t.Fatalf("tail truncation: %v", v)
	}
	_ = last
}

// A database whose privileges were stripped (pg_restore --no-privileges)
// and whose app role disappeared still boots, and grants are re-applied.
func TestBootAfterRestoreLikeState(t *testing.T) {
	d := testutil.NewDB(t)
	k := testutil.RandomKeyBytes()
	s := testutil.Boot(t, d, d.Config(k))
	seed(t, s)
	s.HTTP.Close()
	s.App.Close()
	ctx := t.Context()
	for _, q := range []string{
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ` + d.Role,
		`REVOKE ALL ON SCHEMA public FROM ` + d.Role,
		`REVOKE ALL ON DATABASE ` + d.Name + ` FROM ` + d.Role,
		`DROP ROLE ` + d.Role,
	} {
		if _, err := d.Owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s2 := testutil.Boot(t, d, d.Config(k))
	if s2.App.PoolUser() != d.Role {
		t.Errorf("pool user %q", s2.App.PoolUser())
	}
	o := s2.Client(s2.Login(t, "o@org.test", pw))
	o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets/K", nil)
	o.Must(t, 200, "PUT", "/projects/app/envs/dev/secrets/K", map[string]string{"value": "after"})
	if o.Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"] != true {
		t.Fatal("chain invalid")
	}
}

// If the restricted role cannot be created (non-superuser owner without
// CREATEROLE), the server falls back to the owner connection.
func TestAppRoleFallback(t *testing.T) {
	d := testutil.NewDB(t)
	ctx := t.Context()
	limited := "coffer_lim_" + d.Name[len("coffer_test_"):]
	if _, err := d.Owner.Exec(ctx, `CREATE ROLE `+limited+` LOGIN PASSWORD 'limited-pass' NOSUPERUSER NOCREATEROLE`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgconn.Connect(context.Background(), testutil.DSN(t))
		if err == nil {
			// Separate statements: DROP DATABASE can't run in an implicit tx.
			c.Exec(context.Background(), `DROP DATABASE IF EXISTS `+d.Name+` WITH (FORCE)`).ReadAll()
			c.Exec(context.Background(), `DROP ROLE IF EXISTS `+limited).ReadAll()
			c.Close(context.Background())
		}
	})
	if _, err := d.Owner.Exec(ctx, `ALTER DATABASE `+d.Name+` OWNER TO `+limited+`; GRANT ALL ON SCHEMA public TO `+limited); err != nil {
		t.Fatal(err)
	}
	cfg := d.Config(testutil.RandomKeyBytes())
	cfg.DatabaseURL = strings.Replace(d.DSN, "coffer:coffer@", limited+":limited-pass@", 1)
	if !strings.Contains(cfg.DatabaseURL, limited) {
		t.Skip("cannot rewrite DSN user")
	}
	s := testutil.Boot(t, d, cfg)
	if s.App.PoolUser() != limited {
		t.Errorf("pool user %q, want fallback %q", s.App.PoolUser(), limited)
	}
	seed(t, s)
}

// A second boot (or a boot refused for a wrong master key) against the same
// database must not invalidate the app-role credentials of a running server:
// after its connections are killed (e.g. a DB restart) it reconnects and
// /readyz and the API recover by themselves (SPEC §4 Startup check, §5 Health).
func TestSecondBootKeepsRunningServerConnected(t *testing.T) {
	d := testutil.NewDB(t)
	k := testutil.RandomKeyBytes()
	s1 := testutil.Boot(t, d, d.Config(k))
	if s1.App.PoolUser() != d.Role {
		t.Fatalf("pool user %q, want %q", s1.App.PoolUser(), d.Role)
	}
	o := seed(t, s1)

	// Refused boot: wrong key. Then a successful second instance.
	if err := bootErr(t, d, testutil.RandomKeyBytes(), nil); !errors.Is(err, db.ErrMasterKeyMismatch) {
		t.Fatalf("wrong key boot: %v", err)
	}
	s2 := testutil.Boot(t, d, d.Config(k))
	s2.HTTP.Close()
	s2.App.Close()

	// Drop every app-role session so s1 must open fresh connections.
	ctx := t.Context()
	if _, err := d.Owner.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1`, d.Role); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := s1.Client("").Raw(t, "GET", "/readyz", nil, nil)
		if r.Status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz did not recover: %d %s", r.Status, r.Body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets/K", nil)
	}
}

func TestAppRolePasswordStable(t *testing.T) {
	c := testutil.RandomKeyBytes()
	first, second := db.AppRolePassword(c, "d", "r"), db.AppRolePassword(c, "d", "r")
	if first != second {
		t.Fatal("not deterministic")
	}
	if first == db.AppRolePassword(c, "d2", "r") ||
		first == db.AppRolePassword(testutil.RandomKeyBytes(), "d", "r") {
		t.Fatal("not domain-separated")
	}
}

// SPEC §4 HTTP / §5 Logging: "OPTIONS *" gets the JSON 404 with the standard
// headers instead of net/http's built-in empty 200.
func TestOptionsStarIsJSON404(t *testing.T) {
	d := testutil.NewDB(t)
	s := testutil.Boot(t, d, nil)
	srv := s.App.HTTPServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || string(body) != `{"error":{"code":"not_found","message":"not found"}}` {
		t.Errorf("OPTIONS *: %d %q", resp.StatusCode, body)
	}
	for k, v := range map[string]string{"Content-Type": "application/json", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id")
	}
}

// SPEC §5 Health: /readyz is 200 only while migrations are applied on the
// database behind the running server (e.g. not after it was replaced by an
// empty one), and recovers once they are.
func TestReadyzChecksMigrations(t *testing.T) {
	d := testutil.NewDB(t)
	s := testutil.Boot(t, d, nil)
	anon := s.Client("")
	waitStatus := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			r := anon.Raw(t, "GET", "/readyz", nil, nil)
			if r.Status == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("/readyz %d, want %d", r.Status, want)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitStatus(200)
	ctx := t.Context()
	if _, err := d.Owner.Exec(ctx, `ALTER TABLE schema_migrations RENAME TO schema_migrations_away`); err != nil {
		t.Fatal(err)
	}
	waitStatus(503)
	if _, err := d.Owner.Exec(ctx, `ALTER TABLE schema_migrations_away RENAME TO schema_migrations`); err != nil {
		t.Fatal(err)
	}
	waitStatus(200)
	if _, err := d.Owner.Exec(ctx, `DELETE FROM schema_migrations`); err != nil {
		t.Fatal(err)
	}
	waitStatus(503)
}
