// Package httpapi is the composition root and the HTTP server.
//
// router.go builds the ServeMux, calls one Register per slice package, and installs
// the middleware chain. It contains no business route of its own: every /api/v1
// route is registered by authapi, secretsapi or auditapi, so a slice can add a route
// without this file changing. It is frozen at the end of Stage 0.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"coffer/internal/api/auditapi"
	"coffer/internal/api/authapi"
	"coffer/internal/api/secretsapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/httpx"
	"coffer/internal/idgen"
	"coffer/internal/reqctx"
	"coffer/internal/store"
)

// Deps is what the router hands to each slice. It is the frozen cross-slice surface:
// the database, the audit writer, the configuration and the logger. A slice gets no
// peer's package.
type Deps struct {
	DB     *store.DB
	Audit  audit.Writer
	Config *config.Config
	Log    *slog.Logger
}

// newRootMux is the public surface: only /api/v1 plus the two probes. Everything else
// is the 404 envelope.
//
// It is separate from NewRouter so a test can resolve a path against the real routing
// table, including the probes, which sit outside the API mux.
func newRootMux(deps Deps, apiHandler http.Handler) *http.ServeMux {
	root := http.NewServeMux()
	root.Handle("/api/v1/", apiHandler)
	root.Handle("/api/v1", apiHandler)
	// Method-scoped patterns, so the routing table itself enforces the method. A wrong
	// method then falls to the "/" catch-all and returns the 404 envelope, which is the
	// same answer as an unknown path.
	root.Handle("GET /healthz", healthz())
	root.Handle("GET /readyz", readyz(deps.DB, deps.Log))
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, httpx.NotFound("not found"))
	})
	return root
}

// registerSlices builds the API mux and calls one Register per slice. It is separate
// from NewRouter so a test can inspect the real registrations rather than a copy: the
// route-coverage test asserts every frozen route resolves to a slice's pattern and not
// to the catch-all.
//
// router.go still never learns a route: this function names the three slice packages
// and nothing else.
func registerSlices(deps Deps) *http.ServeMux {
	apiMux := http.NewServeMux()

	authapi.Register(apiMux, authapi.Deps{
		DB:     deps.DB,
		Audit:  deps.Audit,
		Config: deps.Config,
		Log:    deps.Log,
	})
	secretsapi.Register(apiMux, secretsapi.Deps{
		DB:     deps.DB,
		Audit:  deps.Audit,
		Config: deps.Config,
		Log:    deps.Log,
	})
	auditapi.Register(apiMux, auditapi.Deps{
		DB:     deps.DB,
		Audit:  deps.Audit,
		Config: deps.Config,
		Log:    deps.Log,
	})

	// Unknown paths and wrong methods inside /api/v1 must return the 404 envelope,
	// not Go's plain-text 404. This catch-all matches any method on any unmatched API
	// path; the route-coverage test treats a resolution to "/" as "nothing registered".
	apiMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, httpx.NotFound("not found"))
	})

	return apiMux
}

// Middleware is one layer of the chain, outermost first.
type Middleware func(http.Handler) http.Handler

// NewRouter builds the complete handler: the API mux with its middleware chain, plus
// /healthz and /readyz outside it.
//
// deps.Audit may be nil; it becomes a no-op writer so the tree compiles and serves
// before the audit slice lands. deps.Log may be nil.
func NewRouter(deps Deps, authenticator reqctx.Authenticator) http.Handler {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	// A nil audit writer is not silently replaced with a no-op. An audit log that
	// accepts every event and discards it makes the server look healthy while
	// recording nothing, and an empty chain even verifies as valid. The caller has
	// to wire a real writer: ServeWithOptions refuses to boot without one, and a
	// test passes audit.NopWriter() explicitly, which keeps the no-op out of
	// production wiring entirely.
	if deps.Audit == nil {
		panic("httpapi: NewRouter called with a nil audit writer; wire audit.NewAppender or pass audit.NopWriter() in a test")
	}

	apiMux := registerSlices(deps)

	// The chain, outermost first: route pattern, logging, panic recovery, source IP,
	// auth resolution, then the central denial flush.
	trustProxy := deps.Config != nil && deps.Config.TrustProxy
	apiHandler := chain(apiMux,
		withRoutePattern(apiMux),
		withRequestLog(deps.Log),
		withRecover(deps.Log),
		withSourceIP(trustProxy),
		withAuth(authenticator, deps.DB),
		withDenialFlush(deps.Audit, deps.Log),
	)

	root := newRootMux(deps, apiHandler)

	// Outermost: the request id, so every response carries one including the probes
	// and the 404s, and the envelope rewriter, which turns any plain-text 404/405 the
	// mux produces on its own into the frozen error body.
	return withRequestID(withNotFoundEnvelope(withCleanPaths(root)))
}

// withCleanPaths rejects an unclean request path with 404 before the ServeMux can
// redirect it (SPEC §4: the server serves only /api/v1, /healthz and /readyz, and
// "every other path returns 404").
//
// http.ServeMux answers a path that is not in canonical form -- "//api/v1/me",
// "/./api/v1/me", "/api/v1//me" -- with a 307 to the cleaned path. A redirect is
// not a 404: it advertises that a cleaned form exists, and it makes the served
// surface depend on how a proxy or client normalises the path. Rejecting the
// unclean form outright keeps the surface exactly the three prefixes the spec
// names, and keeps a traversal attempt from being answered differently from a
// missing resource.
func withCleanPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p != cleanPath(p) {
			httpx.WriteError(w, r, httpx.NotFound("not found"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanPath is path.Clean for a request path, with the guarantee that a rooted
// path stays rooted. path.Clean("/a/../..") is "/", so the empty-path case cannot
// arise for a real request, but the guard keeps the comparison total.
func cleanPath(p string) string {
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

// chain applies middleware so that the first entry is the outermost layer.
func chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		if mw[i] != nil {
			h = mw[i](h)
		}
	}
	return h
}

// withNotFoundEnvelope turns a plain-text 404 or 405 produced by the ServeMux itself
// into the frozen error envelope.
//
// Go's mux writes its own plain-text "404 page not found" and "405 method not
// allowed" for a path or method it cannot route. Those are reachable — an unknown
// API path, a wrong method on a route registered with a method — and a plain-text
// body would break every client that parses the envelope. This wrapper buffers only
// that one case, so a normal response pays nothing.
func withNotFoundEnvelope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rewriter := &notFoundRewriter{ResponseWriter: w}
		next.ServeHTTP(rewriter, r)
		if rewriter.rewrite {
			httpx.WriteErrorCode(w, http.StatusNotFound, httpx.CodeNotFound, "not found")
		}
	})
}

type notFoundRewriter struct {
	http.ResponseWriter
	wroteHeader bool
	rewrite     bool
}

func (w *notFoundRewriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	contentType := w.Header().Get("Content-Type")
	if (status == http.StatusNotFound || status == http.StatusMethodNotAllowed) &&
		strings.HasPrefix(contentType, "text/plain") {
		// Suppress the mux's own body and status; the wrapper writes the envelope.
		w.rewrite = true
		w.Header().Del("Content-Type")
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *notFoundRewriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.rewrite {
		// Swallow the plain-text body; it is replaced by the envelope.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *notFoundRewriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// withRequestID gives every request an id, returns it in X-Request-Id and puts it in
// the context so the log line and any error report share it.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID(r)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// withRoutePattern records the matched ServeMux pattern on the request context, so
// the request log and any error report name the route rather than the raw path (a
// path can carry an id, and an id can carry a tenant).
//
// It asks the mux for the match instead of reading Request.Pattern, because the
// pattern is only set on the request the mux passes to the matched handler, which is
// below every layer here.
func withRoutePattern(mux *http.ServeMux) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pattern := mux.Handler(r)
			next.ServeHTTP(w, httpx.WithRoutePattern(r, pattern))
		})
	}
}

// withRequestLog writes one JSON line per request. It logs the method, the matched
// route pattern (never the raw path, which could carry an identifier), the status,
// the duration and the request id — and never a body, a header, a token or a value.
func withRequestLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			route := httpx.RoutePattern(r)
			if route == "" {
				route = "unmatched"
			}
			log.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.Int("status", rec.status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("request_id", requestIDFrom(r.Context())),
			)
		})
	}
}

// withRecover turns a panic into a 500 with the standard envelope, and keeps the
// stack trace out of the response. The panic value is logged server-side.
func withRecover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				log.Error("panic recovered",
					"panic", rec,
					"route", httpx.RoutePattern(r),
					"request_id", requestIDFrom(r.Context()),
				)
				httpx.WriteError(w, r, httpx.Internal(errors.New("panic")))
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// isAPIRoute reports whether pattern is a registered API route rather than the
// catch-all. A resolved pattern carries its method ("GET /api/v1/me"), so a request
// that matched no route, or matched a route with the wrong method, is not one.
func isAPIRoute(pattern string) bool {
	if pattern == "" || pattern == "/" {
		return false
	}
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return false
	}
	if method == "" || !strings.HasPrefix(path, "/api/v1/") {
		return false
	}
	return true
}

// publicRoutes are the only API routes reachable without a credential. The set is
// deliberately tiny: a route that hands out a credential cannot itself require one.
//
// It is keyed by the matched ServeMux pattern, which withRoutePattern records before
// withAuth runs, so an unknown path can never match here and fall through unauthenticated.
var publicRoutes = map[string]bool{
	"POST /api/v1/auth/token": true,
}

// withAuth resolves the bearer token into an Actor before any handler runs.
//
// A request with no credential is passed through as anonymous: the public routes
// (login) need that, and every other handler answers 401 itself through its slice.
// A request with a credential that does not resolve is rejected here with 401, so no
// handler ever sees a half-authenticated caller.
func withAuth(authenticator reqctx.Authenticator, db *store.DB) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, present := bearerToken(r)
			if !present {
				// A caller with no credential has no tenant to be invisible from, so
				// this is 401 unauthenticated, not the 404 that means "invisible"
				// (SPEC §7.2, and §2.1's 404 rule governs an authenticated caller).
				//
				// The login route is the one exception: it exists to hand out a
				// credential, so it must be reachable without one. Without this
				// allowlist the ruling would make POST /auth/token itself
				// unreachable and no one could ever sign in.
				pattern := httpx.RoutePattern(r)
				if publicRoutes[pattern] {
					reqctx.SetActor(r, reqctx.Actor{Kind: reqctx.KindAnonymous})
					next.ServeHTTP(w, r)
					return
				}
				// Only a request that actually matches a registered API route is
				// answered 401 here. An unknown path or a wrong method resolves to
				// the catch-all, and CONTRACTS §2 lists both as 404: there is no
				// resource to authenticate against, so asking for a credential
				// would tell an unauthenticated scanner which paths exist.
				if !isAPIRoute(pattern) {
					next.ServeHTTP(w, r)
					return
				}
				httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
				return
			}

			if authenticator == nil {
				// No resolver wired: a presented credential cannot be verified, so
				// the request is unauthenticated. Failing closed here matters — the
				// alternative is treating an unknown token as valid.
				httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
				return
			}

			actor, mustChange, err := resolveActor(r.Context(), authenticator, db, token)
			if err != nil {
				if !errors.Is(err, reqctx.ErrUnauthenticated) {
					// A store failure is a 500, not a 401: a database outage must
					// not look like a bad password.
					httpx.WriteError(w, r, httpx.Internal(err))
					return
				}
				httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
				return
			}
			if actor.IsAnonymous() {
				httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
				return
			}

			reqctx.SetActor(r, actor)

			// The must-change-password flag is set HERE, once, for every slice.
			//
			// Without this, each slice had to re-derive it, and two of them grew a
			// private fallback query to do so. Setting it at the one point where the
			// credential is resolved means reqctx.MustChangePasswordFrom is populated
			// for every route now and for any slice added later.
			r = r.WithContext(reqctx.WithMustChangePassword(r.Context(), mustChange))

			// The gate runs before any handler, so a caller who still has to change
			// their password gets the machine-readable 403 and never a 403 or 404
			// that describes a resource they are not yet allowed to touch.
			if mustChange && !mustChangeExempt(r) {
				reqctx.Deny(r.Context(), denialScope(actor), audit.ActionDenied, "auth/password")
				httpx.WriteErrorCode(w, http.StatusForbidden, CodePasswordChangeRequired,
					"password change required: call POST /api/v1/auth/password (coffer passwd) first")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CodePasswordChangeRequired is the machine-readable 403 code returned while a caller
// still has to change their password (SPEC §4, P1). It matches the code authapi emits
// so a client sees one value regardless of which layer answered.
const CodePasswordChangeRequired = "password_change_required"

// resolveActor resolves the credential and the must-change-password flag together.
//
// An authenticator that implements reqctx.ActorResolver returns the flag from the same
// row it used to prove the credential, so the value is per request and cannot be
// evicted or missed.
//
// An authenticator that only implements the frozen reqctx.Authenticator is still
// accepted, and the flag is treated as SET for a user. That is fail-closed on purpose:
// refusing a caller who has already changed their password is an inconvenience with a
// visible 403 and a documented way out, while admitting a gated caller would hand out
// access the flag exists to withhold. The earlier design used a side map whose miss
// returned "not gated", which is the opposite of fail-closed and let an eviction admit
// every gated user at once.
func resolveActor(ctx context.Context, authenticator reqctx.Authenticator, db *store.DB, token string) (reqctx.Actor, bool, error) {
	if resolver, ok := authenticator.(reqctx.ActorResolver); ok {
		return resolver.Resolve(ctx, token)
	}

	actor, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		return reqctx.Actor{}, false, err
	}

	// The authenticator cannot report the flag, so read it from the database rather
	// than guessing. Guessing "gated" for every user locks out people who have already
	// changed their password; guessing "not gated" admits people who have not. One
	// indexed lookup by user id is the only answer that is both correct and safe.
	//
	// This is the path a wrapper that forwards only Authenticate lands on, which is
	// exactly why it must be a real lookup and not an assumption.
	if !actor.IsUser() || actor.UserID == "" {
		// A service token has no user and the platform admin is created with the flag
		// clear; neither is ever gated.
		return actor, false, nil
	}

	mustChange, err := lookupMustChange(ctx, db, actor.UserID)
	if err != nil {
		// A database failure is not an authorization decision. Refuse rather than
		// admit, and let the error surface as a 500 so the outage is visible.
		return reqctx.Actor{}, false, err
	}
	return actor, mustChange, nil
}

// lookupMustChange reads the flag for a user. It is the fallback for an authenticator
// that cannot report it, and it is a single indexed lookup by primary key.
func lookupMustChange(ctx context.Context, db *store.DB, userID string) (bool, error) {
	if db == nil || db.Pool() == nil {
		// No database to consult. Refuse: an unanswerable gate must not become an open
		// door. In production the pool is always present, so this is a wiring bug
		// caught at the first request rather than a normal path.
		return false, errors.New("httpapi: cannot resolve the must-change-password flag without a database")
	}
	var must bool
	err := db.Pool().QueryRow(ctx,
		`SELECT must_change_password FROM users WHERE id = $1`, userID).Scan(&must)
	if err != nil {
		return false, fmt.Errorf("httpapi: could not read the must-change-password flag: %w", err)
	}
	return must, nil
}

// mustChangeExempt reports whether a route may be called while the caller still has to
// change their password: the route that clears the flag, and logout. Anything else is
// refused until the password is changed.
func mustChangeExempt(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/auth/password", "/api/v1/auth/logout":
		return true
	default:
		return false
	}
}

// denialScope is the chain a denial belongs to: the actor's own organization, or the
// platform chain for a principal that has none.
func denialScope(actor reqctx.Actor) string {
	if actor.OrgID == "" || actor.IsPlatform() {
		return audit.PlatformScope
	}
	return actor.OrgID
}

// bearerToken extracts the token from Authorization: Bearer. A malformed header is
// treated as no credential at all, so it lands on the same 401 path.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// withDenialFlush is the central denial writer. After the handler runs it looks at
// the status: for a 403 or a 404 it writes one `denied` audit event from the
// request's recorder. It never writes for a 401 — an unauthenticated request has no
// actor to attribute, and letting anonymous callers write to the log is a free
// write amplification primitive.
//
// The handler is responsible for calling reqctx.Deny with the action and target; if
// it did not, a generic denial is still recorded, because a 403 that leaves no trace
// is worse than one with a coarse target.
func withDenialFlush(writer audit.Writer, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := &reqctx.Recorder{}
			r = r.WithContext(reqctx.WithRecorder(r.Context(), recorder))

			sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			if sw.status != http.StatusForbidden && sw.status != http.StatusNotFound {
				return
			}

			actor := reqctx.From(r.Context())
			event := denialEvent(r, actor, recorder, sw.status)

			// Use a detached context: the request context is cancelled as soon as
			// the response is written, and the denial must still be recorded.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if _, err := writer.Append(ctx, event); err != nil {
				log.Error("could not record a denied request",
					"error", err.Error(),
					"request_id", requestIDFrom(r.Context()))
			}
		})
	}
}

// denialEvent builds the `denied` event for a 403/404.
func denialEvent(r *http.Request, actor reqctx.Actor, recorder *reqctx.Recorder, status int) audit.Event {
	denial, ok := recorder.First()

	scope := audit.PlatformScope
	if actor.OrgID != "" && !actor.IsPlatform() && !actor.IsAnonymous() {
		scope = actor.OrgID
	}

	action := audit.ActionDenied
	target := ""
	if ok {
		if denial.Action != "" && audit.IsKnownAction(denial.Action) {
			action = denial.Action
		}
		target = denial.Target
	}
	if target == "" {
		route := httpx.RoutePattern(r)
		if route == "" {
			route = r.Method + " " + r.URL.Path
		}
		target = route
	}

	actorID := actor.UserID
	if actorID == "" {
		actorID = actor.TokenID
	}
	if actorID == "" {
		actorID = "anonymous"
	}

	kind := audit.ActorAnonymous
	switch actor.Kind {
	case reqctx.KindUser:
		kind = audit.ActorUser
	case reqctx.KindService:
		kind = audit.ActorService
	case reqctx.KindPlatform:
		kind = audit.ActorPlatform
	}

	orgID := actor.OrgID
	if scope == audit.PlatformScope {
		// The platform chain carries the actor's org only when the actor is an
		// anonymous caller, who has none. Keeping it empty avoids implying the
		// platform admin belongs to an organization.
		orgID = ""
	}

	return audit.Event{
		Scope:     scope,
		Timestamp: time.Now().UTC(),
		ActorID:   actorID,
		ActorKind: kind,
		OrgID:     orgID,
		Action:    action,
		Target:    target,
		SourceIP:  reqctx.SourceIPFrom(r.Context()),
		Result:    audit.ResultDenied,
	}
}

// statusRecorder captures the status code for logging and for the denial flush. It
// also records whether a handler has already written, so the router's fallback 404
// can tell a real 404 from a response it would be overwriting.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.written {
		return
	}
	s.status = status
	s.written = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.written {
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush implements http.Flusher when the underlying writer does.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// healthz reports liveness: the process is up and serving. It never touches the
// database, so a database outage does not get the container restarted.
func healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// readyz reports readiness: the database answers SELECT 1 and every embedded
// migration version is applied. The body names the failing dependency and nothing
// else — no SQL, no host, no path.
func readyz(db *store.DB, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"reason": "database",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			log.Debug("readyz: database ping failed", "error", err.Error())
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"reason": "database",
			})
			return
		}

		// Reaching here means the pool answered, so a schema problem is reported as
		// "migrations". Any other failure is still a database problem, which keeps a
		// genuine outage from being labelled a migration issue.
		if err := db.MigrationsApplied(ctx); err != nil {
			reason := "database"
			if errors.Is(err, store.ErrMigrationsIncomplete) {
				reason = "migrations"
			}
			log.Warn("readyz: not ready", "reason", reason, "error", err.Error())
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"reason": reason,
			})
			return
		}

		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

// requestID returns the caller's X-Request-Id when it is a plausible id, otherwise a
// fresh one. A caller-supplied id is trusted only for length and character class so
// it cannot inject a newline into the log or the header.
func requestID(r *http.Request) string {
	if candidate := r.Header.Get("X-Request-Id"); candidate != "" && validRequestID(candidate) {
		return candidate
	}
	return idgenRequestID()
}

func validRequestID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// idgenRequestID returns a 12-byte hex id, the same shape as every other Coffer id.
func idgenRequestID() string {
	return idgen.New("")
}

// remoteIP resolves the client address: the socket peer, or, when the operator has
// set COFFER_TRUST_PROXY, the rightmost X-Forwarded-For entry that is not a trusted
// proxy. This is the same value the login throttle must use, so a rotated header
// cannot buy extra attempts.
func remoteIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := rightmostUntrusted(r); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func rightmostUntrusted(r *http.Request) string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return ""
	}
	// Later headers are appended by closer proxies; the last entry of the last
	// header is the one the nearest trusted proxy saw.
	var entries []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				entries = append(entries, trimmed)
			}
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if net.ParseIP(entries[i]) != nil {
			return entries[i]
		}
	}
	return ""
}

// withSourceIP records the resolved client address on the context. It is part of the
// auth layer because the resolver needs the configuration, and it must run before any
// handler or throttle reads it.
func withSourceIP(trustProxy bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := reqctx.WithSourceIP(r.Context(), remoteIP(r, trustProxy))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
