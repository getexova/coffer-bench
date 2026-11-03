package authapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"net/http"

	"coffer/internal/audit"
	"coffer/internal/httpx"
	"coffer/internal/reqctx"
)

// Middleware is this slice's complete authentication wrapper: it resolves the
// source IP, installs the denial recorder, authenticates the bearer token when one
// is presented, applies the must-change-password gate, and flushes one `denied`
// audit event for a 403 or 404 that came from an authorization decision.
//
// router.go may install this directly (`handler = authapi.Middleware(deps)(mux)`)
// or use NewAuthenticator inside its own chain; both are correct, and every handler
// also calls gate() and requireActor(), so the rules hold either way.
//
// A request without a token is passed to the mux unchanged. That is deliberate: an
// unknown path must still answer 404 (docs/CONTRACTS.md §2), and a known route
// answers 401 from its handler. One source of truth for each status.
func (d Deps) Middleware(next http.Handler) http.Handler {
	a := &api{Deps: d, limits: newLimiter()}
	return a.middleware(next)
}

func (a *api) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.WithSourceIP(r.Context(), SourceIP(r, a.trustProxy()))
		recorder := &reqctx.Recorder{}
		ctx = reqctx.WithRecorder(ctx, recorder)
		r = r.WithContext(ctx)

		if token := bearerToken(r); token != "" && !isPublicRoute(r) {
			actor, err := NewAuthenticator(a.Deps).Authenticate(r.Context(), token)
			switch {
			case err == nil:
				reqctx.SetActor(r, actor)
				// The must-change flag is read once, here, from the credential that
				// just resolved; handlers read it back from the context. One query
				// per request, and it is the same query that proves the credential
				// is still live.
				if actor.IsUser() && actor.TokenID != "" {
					must := a.mustChangeForToken(r.Context(), actor.TokenID)
					r = r.WithContext(reqctx.WithMustChangePassword(r.Context(), must))
					if must && !isMustChangeExempt(r) {
						// Written directly rather than recorded: this branch returns
						// before next.ServeHTTP, so no flush will run for it. One
						// denial, one event, exactly as a handler-level refusal.
						a.writeDenial(r, reqctx.Denial{
							Scope:  scopeFor(actor),
							Action: audit.ActionDenied,
							Target: "auth/password",
						})
						httpx.WriteErrorCode(w, http.StatusForbidden, CodePasswordChangeRequired,
							"password change required: call POST /api/v1/auth/password (coffer passwd) first")
						return
					}
				}
			case errors.Is(err, reqctx.ErrUnauthenticated):
				// Leave the actor anonymous: the handler answers 401, and an unknown
				// path still answers 404.
			default:
				a.logger().Error("auth: resolve credential", "error", err)
				httpx.WriteError(w, r, httpx.Internal(err))
				return
			}
		}

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		a.flushDenial(r, sw.status, recorder)
	})
}

// trustProxy reports whether the trusted-proxy header may be honoured.

// trustProxy reports whether the trusted-proxy header may be honoured.
func (a *api) trustProxy() bool {
	return a.Config != nil && a.Config.TrustProxy
}

// statusWriter records the status code so the denial flush can decide whether the
// response was a refusal.

// statusWriter records the status code so the denial flush can decide whether the
// response was a refusal.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// flushDenial writes the single `denied` audit event for a refused request.
//
// It runs AFTER the response status is known, and it never asks whether the target
// exists: the event describes what the caller tried, not what the server found, so
// a denial for another organization's resource cannot reveal that the resource is
// there.

// flushDenial writes the single `denied` audit event for a refused request.
//
// It runs AFTER the response status is known, and it never asks whether the target
// exists: the event describes what the caller tried, not what the server found, so
// a denial for another organization's resource cannot reveal that the resource is
// there.
func (a *api) flushDenial(r *http.Request, status int, rec *reqctx.Recorder) {
	if status != http.StatusForbidden && status != http.StatusNotFound {
		return
	}
	denial, ok := rec.First()
	if !ok {
		return
	}
	a.writeDenial(r, denial)
}

// writeDenial applies the denial budget and writes the event.

// writeDenial applies the denial budget and writes the event.
func (a *api) writeDenial(r *http.Request, denial reqctx.Denial) {
	actor := reqctx.From(r.Context())
	sourceIP := reqctx.SourceIPFrom(r.Context())

	allowed, dropped := a.limits.denials.allow(sourceIP, time.Now())
	if dropped > 0 {
		a.logger().Warn("audit: denial events dropped by rate limit", "dropped", dropped)
	}
	if !allowed {
		return
	}

	scope := denial.Scope
	if scope == "" {
		scope = audit.PlatformScope
	}
	ev := audit.Event{
		Scope:     scope,
		Timestamp: time.Now().UTC(),
		ActorID:   actorID(actor),
		ActorKind: actorKind(actor),
		OrgID:     orgOf(actor),
		Action:    audit.ActionDenied,
		Target:    denial.Target,
		SourceIP:  sourceIP,
		Result:    audit.ResultDenied,
	}
	if _, err := a.writer().Append(r.Context(), ev); err != nil {
		a.logger().Error("audit: append denial", "error", err)
	}
}

// actorID is the actor's token or user id, never an email and never a credential.

// actorID is the actor's token or user id, never an email and never a credential.
func actorID(actor reqctx.Actor) string {
	if actor.TokenID != "" {
		return actor.TokenID
	}
	return actor.UserID
}

// actorKind maps a reqctx actor onto the frozen audit actor kinds.

// actorKind maps a reqctx actor onto the frozen audit actor kinds.
func actorKind(actor reqctx.Actor) audit.ActorKind {
	switch {
	case actor.IsAnonymous():
		return audit.ActorAnonymous
	case actor.IsService():
		return audit.ActorService
	case actor.IsPlatform():
		return audit.ActorPlatform
	default:
		return audit.ActorUser
	}
}

// orgOf returns the actor's organization, empty for the platform admin and for
// anonymous callers.

// orgOf returns the actor's organization, empty for the platform admin and for
// anonymous callers.
func orgOf(actor reqctx.Actor) string {
	if actor.IsPlatform() || actor.IsAnonymous() {
		return ""
	}
	return actor.OrgID
}

// scopeFor is the audit chain a caller's own actions belong to: its organization,
// or the platform chain when it has none. The scope is always explicit, so an
// org-scoped event can never silently land on the platform chain.

// scopeFor is the audit chain a caller's own actions belong to: its organization,
// or the platform chain when it has none. The scope is always explicit, so an
// org-scoped event can never silently land on the platform chain.
func scopeFor(actor reqctx.Actor) string {
	if actor.IsPlatform() || actor.IsAnonymous() || actor.OrgID == "" {
		return audit.PlatformScope
	}
	return actor.OrgID
}

// auditEvent builds an event in the actor's own chain, with the source IP already
// filled in from the request context.

// auditEvent builds an event in the actor's own chain, with the source IP already
// filled in from the request context.
func (a *api) auditEvent(ctx context.Context, actor reqctx.Actor, action, target string, result audit.Result) audit.Event {
	return audit.Event{
		Scope:     scopeFor(actor),
		Timestamp: time.Now().UTC(),
		ActorID:   actorID(actor),
		ActorKind: actorKind(actor),
		OrgID:     orgOf(actor),
		Action:    action,
		Target:    target,
		SourceIP:  reqctx.SourceIPFrom(ctx),
		Result:    result,
	}
}

// appendAudit writes one event on its own transaction. A failure is logged and
// never fails the request: the business change already committed, and turning that
// into a 500 would tell the caller their write did not happen when it did.

// appendAudit writes one event on its own transaction. A failure is logged and
// never fails the request: the business change already committed, and turning that
// into a 500 would tell the caller their write did not happen when it did.
func (a *api) appendAudit(ctx context.Context, ev audit.Event) {
	if _, err := a.writer().Append(ctx, ev); err != nil {
		a.logger().Error("audit: append", "action", ev.Action, "error", err)
	}
}

// appendAuditTx writes one event inside the caller's transaction, so a business
// change and its audit record commit or roll back together.

// appendAuditTx writes one event inside the caller's transaction, so a business
// change and its audit record commit or roll back together.
func (a *api) appendAuditTx(ctx context.Context, tx pgx.Tx, ev audit.Event) error {
	if _, err := a.writer().AppendTx(ctx, tx, ev); err != nil {
		return fmt.Errorf("authapi: append audit %s: %w", ev.Action, err)
	}
	return nil
}

// deny records and answers an authorization refusal. It is called only when the
// caller CAN see the resource but may not act on it, which is what makes 403
// different from 404.

// deny records and answers an authorization refusal. It is called only when the
// caller CAN see the resource but may not act on it, which is what makes 403
// different from 404.
func (a *api) deny(w http.ResponseWriter, r *http.Request, target string) {
	a.recordDenial(r, target)
	httpx.WriteError(w, r, httpx.Forbidden("not permitted"))
}

// hide records and answers an invisibility refusal. The body is the same one a
// genuinely missing resource produces.

// hide records and answers an invisibility refusal. The body is the same one a
// genuinely missing resource produces.
func (a *api) hide(w http.ResponseWriter, r *http.Request, target string) {
	a.recordDenial(r, target)
	httpx.WriteError(w, r, httpx.NotFound("not found"))
}

// recordDenial hands the denial to the request recorder when middleware installed
// one, and otherwise writes it immediately. Exactly one writer either way.

// recordDenial hands the denial to the request recorder when middleware installed
// one, and otherwise writes it immediately. Exactly one writer either way.
func (a *api) recordDenial(r *http.Request, target string) {
	actor := reqctx.From(r.Context())
	scope := scopeFor(actor)
	if reqctx.RecorderFrom(r.Context()) != nil {
		reqctx.Deny(r.Context(), scope, audit.ActionDenied, target)
		return
	}
	a.writeDenial(r, reqctx.Denial{Scope: scope, Action: audit.ActionDenied, Target: target})
}

// gate enforces the must-change-password rule for one request (SPEC §4 P1(a)).
//
// It is deny-by-default: the only routes that pass are the two on the exempt list,
// so a route added later is gated without anyone remembering to add it. It returns
// true when the caller may proceed.

// gate enforces the must-change-password rule for one request (SPEC §4 P1(a)).
//
// It is deny-by-default: the only routes that pass are the two on the exempt list,
// so a route added later is gated without anyone remembering to add it. It returns
// true when the caller may proceed.
func (a *api) gate(w http.ResponseWriter, r *http.Request) bool {
	if !a.mustChangePassword(r) {
		return true
	}
	if isMustChangeExempt(r) {
		return true
	}
	a.recordDenial(r, "auth/password")
	httpx.WriteErrorCode(w, http.StatusForbidden, CodePasswordChangeRequired,
		"password change required: call POST /api/v1/auth/password (coffer passwd) first")
	return false
}

// mustChangePassword reports the flag from the request context, falling back to the
// resolved credential when middleware did not carry it. The answer is cached back
// into the request context, so a handler that checks the gate more than once costs
// one indexed query, not one per check.

// mustChangePassword reports the flag from the request context, falling back to the
// resolved credential when middleware did not carry it. The answer is cached back
// into the request context, so a handler that checks the gate more than once costs
// one indexed query, not one per check.
func (a *api) mustChangePassword(r *http.Request) bool {
	if reqctx.MustChangePasswordFrom(r.Context()) {
		return true
	}
	actor := reqctx.From(r.Context())
	if !actor.IsUser() || actor.TokenID == "" {
		return false
	}
	must := a.mustChangeForToken(r.Context(), actor.TokenID)
	if must {
		// In-place, so the next call in this request sees it without another query.
		*r = *r.WithContext(reqctx.WithMustChangePassword(r.Context(), true))
	}
	return must
}

// mustChangeForToken reads the flag from the token's own row. The predicate repeats
// the liveness conditions of token resolution, so a credential revoked between
// resolution and this read reports "no flag" and the handler's own lookup then
// answers 401 rather than the handler running on a dead session.

// mustChangeForToken reads the flag from the token's own row. The predicate repeats
// the liveness conditions of token resolution, so a credential revoked between
// resolution and this read reports "no flag" and the handler's own lookup then
// answers 401 rather than the handler running on a dead session.
func (a *api) mustChangeForToken(ctx context.Context, tokenID string) bool {
	conn := a.conn()
	if conn == nil {
		return false
	}
	var must bool
	err := conn.QueryRow(ctx,
		`SELECT u.must_change_password
		   FROM personal_access_tokens t
		   JOIN users u ON u.id = t.user_id
		  WHERE t.id = $1 AND t.revoked_at IS NULL AND u.removed_at IS NULL`,
		tokenID).Scan(&must)
	if err != nil {
		return false
	}
	return must
}

// requireActor returns the caller and answers 401 when there is none. It is the
// fail-closed guard at the top of every handler.
//
// It also applies the must-change-password gate, which is why every handler calls it
// first: the gate must run BEFORE any role or visibility check, so a caller who still
// has to change their password gets the machine-readable 403 and never a 403 or 404
// that describes a resource they are not yet allowed to touch. The two exempt routes
// pass because isMustChangeExempt names them.

// requireActor returns the caller and answers 401 when there is none. It is the
// fail-closed guard at the top of every handler.
//
// It also applies the must-change-password gate, which is why every handler calls it
// first: the gate must run BEFORE any role or visibility check, so a caller who still
// has to change their password gets the machine-readable 403 and never a 403 or 404
// that describes a resource they are not yet allowed to touch. The two exempt routes
// pass because isMustChangeExempt names them.
func (a *api) requireActor(w http.ResponseWriter, r *http.Request) (reqctx.Actor, bool) {
	actor := reqctx.From(r.Context())
	if actor.IsAnonymous() {
		httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
		return actor, false
	}
	if !a.gate(w, r) {
		return actor, false
	}
	return actor, true
}

// canWrite reports whether a grant level permits a write (SPEC §2.4). It is a pure
// predicate on the stored level, kept here so the rule has one home.
