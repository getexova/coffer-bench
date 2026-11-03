package auditapi

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"coffer/internal/audit"
	"coffer/internal/authz"
	"coffer/internal/httpx"
	"coffer/internal/reqctx"
	"coffer/internal/store"
	"coffer/internal/store/auditq"
)

// codePasswordChangeRequired is the machine-readable 403 code for a caller who must
// change their password before doing anything else (SPEC §4 P1(a)).
//
// It is the same string authapi exports as CodePasswordChangeRequired. It is declared
// here rather than imported because each slice defines its own Deps and imports no
// peer's package (docs/CONTRACTS.md §1); the value is frozen by the contract, not by
// the identifier, and the CLI maps on the string.
const codePasswordChangeRequired = "password_change_required"

// mustChangePasswordDenial is the message authapi returns for the same refusal, so a
// client sees one identical answer whichever slice refused it.
const mustChangePasswordDenial = "password change required: call POST /api/v1/auth/password (coffer passwd) first"

// api holds the dependencies the handlers need. It is built once by Register.
type api struct {
	Deps
	store *auditq.Store
}

func newAPI(deps Deps) *api {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Audit == nil {
		deps.Audit = audit.NopWriter()
	}
	return &api{Deps: deps, store: auditq.New(deps.DB)}
}

// gate enforces the must-change-password rule (SPEC §4 P1(a)) and reports whether the
// caller may proceed.
//
// It is defence in depth, not the primary control. The rule is enforced centrally by
// httpapi.withAuth, which resolves the credential, reads the flag once, puts it on the
// request context and refuses before any handler runs — so this check is a map read,
// not a query, and a request that reaches here has already passed the central gate.
// internal/httpapi/mustchange_central_test.go proves that, with a handler that has no
// local gate of its own.
//
// It stays because it is free and because it keeps the ordering guarantee inside this
// slice: the gate runs BEFORE any authorization check, so if someone later bypasses or
// reorders the router's chain, a caller who has not yet changed their initial password
// still gets the machine-readable 403 and never a 403 or 404 that describes a resource
// they are not yet allowed to touch. The audit log is the most sensitive of those — it
// names every actor, action and target in the organization — so the window between
// account creation and first password change is exactly what the rule exists to close.
//
// It reads ONLY the request context. It deliberately does not fall back to a database
// lookup of the flag: withAuth now populates it for every request, so such a query
// would be pure per-request cost, and a slice-local copy of the lookup would be a
// second place for the rule to drift from the one in the composition root.
//
// None of this slice's four routes is exempt: the exempt list is POST /auth/password
// and POST /auth/logout, and every route here is a GET.
func (a *api) gate(w http.ResponseWriter, r *http.Request) bool {
	if !reqctx.MustChangePasswordFrom(r.Context()) {
		return true
	}
	actor := reqctx.From(r.Context())
	scope := audit.PlatformScope
	if actor.OrgID != "" && !actor.IsPlatform() && !actor.IsAnonymous() {
		scope = actor.OrgID
	}
	reqctx.Deny(r.Context(), scope, audit.ActionDenied, "auth/password")
	httpx.WriteErrorCode(w, http.StatusForbidden, codePasswordChangeRequired, mustChangePasswordDenial)
	return false
}

func (a *api) logger() *slog.Logger {
	if a == nil || a.Log == nil {
		return slog.Default()
	}
	return a.Log
}

// verifyResponse is the whole body of a verify route, fixed by SPEC §7.2:
// exactly {"valid": bool, "first_invalid_seq": number|null}.
//
// FirstInvalidSeq is a *int64 so that a valid chain serialises the field as JSON
// null rather than as 0. A plain int64 would emit 0, and 0 is not a valid sequence
// number — a client reading it would report "invalid at sequence 0". There are no
// other fields: the finding kind and the explanation go to the server log, because
// the response shape is frozen and because naming the kind to an API caller would
// describe the tamper technique to whoever is probing the chain.
type verifyResponse struct {
	Valid           bool   `json:"valid"`
	FirstInvalidSeq *int64 `json:"first_invalid_seq"`
}

// listResponse wraps the page of events. The wrapper is the agreed CLI contract
// (E4 decodes it first and falls back to a bare array), and it leaves room to add a
// field without breaking a client that decodes a bare array.
type listResponse struct {
	Events []auditq.Event `json:"events"`
}

// --- authorization -------------------------------------------------------------

// requireOrgAudit is the guard for the organization routes. It returns the actor and
// true only when the caller may read its own organization's log.
//
// The order of the checks is the rule, not an implementation detail:
//
//	anonymous      -> 401  there is no actor to attribute a denial to
//	platform admin -> 404  every organization-scoped route is invisible to it
//	service token  -> 403  visible organization, no permission (SPEC §2 rule 7)
//	plain member   -> 403  visible organization, no permission (SPEC §2 rule 6)
//	owner / admin  -> allowed
func (a *api) requireOrgAudit(w http.ResponseWriter, r *http.Request, action, target string) (reqctx.Actor, bool) {
	actor := reqctx.From(r.Context())

	if actor.IsAnonymous() {
		// A 401 is never recorded as a denial: an unauthenticated request has no
		// actor, and letting anonymous callers write to the log is a free write
		// amplification primitive (see reqctx's package comment).
		httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
		return actor, false
	}

	if actor.IsPlatform() {
		// The platform admin can never read an organization's audit log (SPEC §2
		// rule 10). 404, and the body is the same one an unknown path produces, so
		// this reveals nothing about whether the organization exists.
		reqctx.Deny(r.Context(), audit.PlatformScope, action, target)
		httpx.WriteError(w, r, httpx.NotFound("not found"))
		return actor, false
	}

	if actor.OrgID == "" {
		// A user with no organization is not a shape the product creates. Treat it as
		// invisible rather than crashing on an empty scope, which would otherwise read
		// the platform chain.
		reqctx.Deny(r.Context(), audit.PlatformScope, action, target)
		httpx.WriteError(w, r, httpx.NotFound("not found"))
		return actor, false
	}

	if !authz.CanReadAudit(actor) {
		// Visible organization, insufficient permission: a service token or a plain
		// member. The denial lands on the caller's own organization chain.
		reqctx.Deny(r.Context(), actor.OrgID, action, target)
		httpx.WriteError(w, r, httpx.Forbidden("not permitted"))
		return actor, false
	}

	return actor, true
}

// requirePlatformAdmin is the guard for the platform routes. Anyone who is not the
// platform admin gets 403: the platform log is not a tenant resource, so there is no
// invisibility rule to apply and a 404 would only mislead the caller.
func (a *api) requirePlatformAdmin(w http.ResponseWriter, r *http.Request, action, target string) (reqctx.Actor, bool) {
	actor := reqctx.From(r.Context())

	if actor.IsAnonymous() {
		httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
		return actor, false
	}
	if !authz.IsPlatformAdmin(actor) {
		scope := audit.PlatformScope
		if actor.OrgID != "" {
			// An organization user's denial belongs on its own chain, so the tenant can
			// see that one of its members probed the platform log.
			scope = actor.OrgID
		}
		reqctx.Deny(r.Context(), scope, action, target)
		httpx.WriteError(w, r, httpx.Forbidden("not permitted"))
		return actor, false
	}
	return actor, true
}

// --- handlers ------------------------------------------------------------------

// handleOrgAudit implements GET /api/v1/audit.
func (a *api) handleOrgAudit(w http.ResponseWriter, r *http.Request) {
	// The must-change gate runs before any authorization check, so a caller who has
	// not yet changed their initial password never learns anything about the log.
	if !a.gate(w, r) {
		return
	}
	actor, ok := a.requireOrgAudit(w, r, audit.ActionDenied, "audit")
	if !ok {
		return
	}
	a.writeLog(w, r, actor.OrgID)
}

// handleOrgAuditVerify implements GET /api/v1/audit/verify.
func (a *api) handleOrgAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !a.gate(w, r) {
		return
	}
	actor, ok := a.requireOrgAudit(w, r, audit.ActionDenied, "audit/verify")
	if !ok {
		return
	}
	a.writeVerify(w, r, actor.OrgID)
}

// handlePlatformAudit implements GET /api/v1/admin/audit.
func (a *api) handlePlatformAudit(w http.ResponseWriter, r *http.Request) {
	if !a.gate(w, r) {
		return
	}
	if _, ok := a.requirePlatformAdmin(w, r, audit.ActionDenied, "admin/audit"); !ok {
		return
	}
	a.writeLog(w, r, audit.PlatformScope)
}

// handlePlatformAuditVerify implements GET /api/v1/admin/audit/verify.
func (a *api) handlePlatformAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !a.gate(w, r) {
		return
	}
	if _, ok := a.requirePlatformAdmin(w, r, audit.ActionDenied, "admin/audit/verify"); !ok {
		return
	}
	a.writeVerify(w, r, audit.PlatformScope)
}

// writeLog answers a list route for one scope. scope is always taken from the
// authenticated actor or the literal platform constant, never from a request
// parameter, so a caller cannot read another tenant's chain by naming it.
func (a *api) writeLog(w http.ResponseWriter, r *http.Request, scope string) {
	filter, ok := a.parseFilter(w, r, scope)
	if !ok {
		return
	}

	events, err := a.store.List(r.Context(), filter)
	if err != nil {
		a.logger().Error("audit: could not read the audit log", "scope", scope, "error", err.Error())
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if events == nil {
		// A nil slice would serialise as null; an empty log is an empty list.
		events = []auditq.Event{}
	}
	httpx.WriteJSON(w, http.StatusOK, listResponse{Events: events})
}

// writeVerify answers a verify route for one scope.
//
// A broken chain is a 200 with valid:false, not an error: the request succeeded in
// answering the question. A non-nil error from audit.Verify means the check could not
// be performed at all, which is a 500 worth retrying.
func (a *api) writeVerify(w http.ResponseWriter, r *http.Request, scope string) {
	verdict, err := audit.Verify(r.Context(), a.store, scope)
	if err != nil {
		a.logger().Error("audit: verification could not run", "scope", scope, "error", err.Error())
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// The distinct message lives here, in the server log, and not in the API body:
	// the body is frozen at two fields, and telling a caller whether they hit a
	// truncation or a column edit describes the tamper technique to whoever is probing.
	verdict.LogFinding(a.logger())

	// Verification writes nothing — no audit event, no repair, no head correction.
	//
	// This is deliberate and it is the one place the brief's "and an audit event"
	// cannot be honoured: the frozen action list (docs/CONTRACTS.md §3) has no action
	// for an audit-integrity finding, and inventing one is forbidden by the same
	// contract. Appending here would also mean writing to the very chain just proved
	// broken: if the finding is a head/events disagreement the append is likely to
	// fail, and if it succeeds it would add an event to a chain whose tail is already
	// untrustworthy. The finding is reported through the server log, which is where an
	// operator's alerting reads it. Adding `audit.verify_failed` to the frozen list
	// needs a DECISIONS.md entry and a migration, and is not this slice's to make.

	httpx.WriteJSON(w, http.StatusOK, verifyResponse{
		Valid:           verdict.Valid,
		FirstInvalidSeq: verdict.FirstInvalid(),
	})
}

// parseFilter reads the frozen query parameters. A malformed value is a 400: silently
// ignoring a filter would return a page the caller did not ask for and could hide the
// events they were investigating.
func (a *api) parseFilter(w http.ResponseWriter, r *http.Request, scope string) (auditq.Filter, bool) {
	query := r.URL.Query()
	filter := auditq.Filter{
		Scope:  scope,
		Actor:  strings.TrimSpace(query.Get("actor")),
		Action: strings.TrimSpace(query.Get("action")),
	}

	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			httpx.WriteError(w, r, httpx.Validation("limit must be an integer"))
			return auditq.Filter{}, false
		}
		if limit < 0 {
			httpx.WriteError(w, r, httpx.Validation("limit must not be negative"))
			return auditq.Filter{}, false
		}
		// A limit above the cap is clamped rather than refused, and zero means the
		// default. auditq applies both rules; passing the value through keeps the one
		// definition of them in the query layer.
		filter.Limit = limit
	}

	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			// RFC3339 only. RFC3339Nano would accept a value whose sub-microsecond
			// digits cannot be compared meaningfully against a timestamptz column.
			httpx.WriteError(w, r, httpx.Validation("since must be an RFC3339 timestamp"))
			return auditq.Filter{}, false
		}
		filter.Since = since
	}

	// actor and action are matched exactly and are passed through as bound parameters.
	// They are deliberately not validated against the frozen action list: an action
	// name this build does not know is still a legitimate filter, and refusing it
	// would break a client written against a later list. An unknown value simply
	// matches nothing.
	return filter, true
}

// Compile-time assertions that the handlers have the shape http.HandlerFunc needs,
// and that the store satisfies the verifier's scanner interface. They cost nothing
// and fail the build rather than a request.
var (
	_ http.HandlerFunc = (&api{}).handleOrgAudit
	_ http.HandlerFunc = (&api{}).handleOrgAuditVerify
	_ http.HandlerFunc = (&api{}).handlePlatformAudit
	_ http.HandlerFunc = (&api{}).handlePlatformAuditVerify

	_ audit.EventScanner = (*auditq.Store)(nil)

	// A *store.DB is what Deps carries; auditq.New accepts it directly.
	_ func(*store.DB) *auditq.Store = auditq.New
)
