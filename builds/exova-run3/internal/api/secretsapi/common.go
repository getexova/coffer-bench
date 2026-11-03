package secretsapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"coffer/internal/audit"
	"coffer/internal/authz"
	"coffer/internal/httpx"
	"coffer/internal/reqctx"
	"coffer/internal/store/secrets"
)

// Error messages. Stable and generic: no SQL, no path, no value, and nothing that distinguishes
// "does not exist" from "not yours".
const (
	msgNotFound   = "not found"
	msgForbidden  = "forbidden"
	msgConflict   = "version conflict"
	msgStale      = "change is stale"
	msgResolved   = "change already resolved"
	msgBadKey     = "invalid key"
	msgBadValue   = "invalid value"
	msgBadVersion = "invalid version"
	msgBadFormat  = "invalid export format"
	msgBadStatus  = "invalid status"
)

// resolved is a request's authorisation outcome: the scope, the actor and the capability level.
type resolved struct {
	actor   reqctx.Actor
	scope   secrets.Scope
	level   string
	project string
	env     string
}

// actorRef is the audit/write identity for the actor. A service token acts as itself: its token id
// is the actor, so an audit row names the machine credential rather than the human who minted it.
func actorRef(a reqctx.Actor) secrets.ActorRef {
	if a.IsService() {
		return secrets.ActorRef{ID: a.TokenID, Kind: string(audit.ActorService)}
	}
	return secrets.ActorRef{ID: a.UserID, Kind: string(audit.ActorUser)}
}

// target builds the stable audit target for a secret: its addressable coordinates and its key.
// It never contains a value or a token.
func target(projectSlug, envSlug, key string) string {
	t := "project/" + projectSlug + "/env/" + envSlug
	if key != "" {
		t += "/key/" + key
	}
	return t
}

// resolveScope resolves {p} and {e} for the caller and applies a capability check.
//
// Order matters and is fixed by the spec:
//  1. A caller with no organization (platform admin, anonymous) gets 404, because an
//     organization-scoped route is not part of what it can see at all (§2.10).
//  2. The project and environment are resolved with org_id in the SQL predicate, so another
//     organization's project is indistinguishable from a missing one.
//  3. A member with no grant, and a service token pointing at another project or environment, are
//     invisible: 404.
//  4. Only a caller that can see the resource but lacks the capability gets 403.
//
// action is the audit action the request was attempting, recorded with a denial so the log says
// what was tried rather than only that something was refused.
func (h *handler) resolveScope(w http.ResponseWriter, r *http.Request, action string, can func(reqctx.Actor, string, string, string) bool) (resolved, bool) {
	ctx := r.Context()
	actor := reqctx.From(ctx)
	projectSlug := r.PathValue("p")
	envSlug := r.PathValue("e")
	key := r.PathValue("key")

	// 1. No organization: invisible.
	if actor.OrgID == "" {
		h.deny(ctx, actor, action, target(projectSlug, envSlug, key))
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
		return resolved{}, false
	}

	sc, err := h.store.ResolveScope(ctx, actor.OrgID, projectSlug, envSlug, actor.UserID)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			// 2 and 3: not in this organization, no grant, or outside a service token's scope.
			h.deny(ctx, actor, action, target(projectSlug, envSlug, key))
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return resolved{}, false
		}
		httpx.WriteError(w, r, httpx.Internal(err))
		return resolved{}, false
	}

	// 4. Visibility and capability are two different questions, and the status depends on which one
	// fails.
	//
	// CanView is the "can the caller see this at all" question, and it is what decides 404. A
	// member with no grant, a platform admin and a service token pointed at another project or
	// environment are all invisible here: none of them may learn that the resource exists, so all
	// of them get the same 404 a missing project gets (§2.1, §2.7).
	if !authz.CanView(actor, sc.ProjectID, sc.EnvID, sc.Grant) {
		h.deny(ctx, actor, action, target(projectSlug, envSlug, key))
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
		return resolved{}, false
	}

	// 5. The resource is visible, so a missing capability is a 403: a viewer reading a value, or a
	// read-only service token attempting a write.
	if !can(actor, sc.ProjectID, sc.EnvID, sc.Grant) {
		h.deny(ctx, actor, action, target(projectSlug, envSlug, key))
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
		return resolved{}, false
	}

	return resolved{
		actor:   actor,
		scope:   sc,
		level:   authz.Effective(actor, sc.ProjectID, sc.EnvID, sc.Grant),
		project: projectSlug,
		env:     envSlug,
	}, true
}

// passwordChangeRequiredCode is the error code authapi uses for the must-change gate, so the CLI
// maps every gated route to the same hint and the same behaviour.
const passwordChangeRequiredCode = "password_change_required"

// msgPasswordChangeRequired is the stable message authapi returns for the same refusal.
const msgPasswordChangeRequired = "password change required: call POST /api/v1/auth/password (coffer passwd) first"

// gateMustChangePassword refuses a caller whose password is still the one an administrator set.
//
// SPEC §4 (P1): a user created with an initial password must change it before doing anything else.
// Until they do, they have not proven they are the person the administrator intended, so they must
// not read secrets or pending change requests.
//
// The rule is enforced centrally: withAuth resolves the flag once, from the same query that proves
// the credential is live, and puts it on the context (internal/httpapi/mustchange_central_test.go
// fails loudly if that stops being true). This check is defence in depth on the routes that expose
// secret values, and it is deliberately a context read only — no database access. Re-resolving the
// flag here would add a query to every secret read, which is the hottest path in the product, to
// answer a question the middleware has already answered.
//
// Every handler calls it first, before resolution and before authorization, so a gated caller cannot
// even learn whether a project exists.
//
// A service token is exempt, and the flag is only ever set for a user credential, so a machine
// credential passes through here without a special case.
func (h *handler) gateMustChangePassword(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	if !reqctx.MustChangePasswordFrom(ctx) {
		return true
	}
	h.deny(ctx, reqctx.From(ctx), audit.ActionDenied, "auth/password")
	httpx.WriteErrorCode(w, http.StatusForbidden, passwordChangeRequiredCode, msgPasswordChangeRequired)
	return false
}

// deny records the first authorization denial on the request.
//
// The middleware flushes it as a `denied` audit event; a handler never writes that event itself, so
// a 403 or 404 cannot be audited twice and cannot be forgotten. The scope is the actor's own
// organization — never the target's, which a caller who cannot see the target does not know, and
// writing into it would leak the existence of another tenant's resource.
func (h *handler) deny(ctx context.Context, actor reqctx.Actor, action, tgt string) {
	scope := actor.OrgID
	if scope == "" {
		scope = audit.PlatformScope
	}
	reqctx.Deny(ctx, scope, action, tgt)
}

// newEvent builds the audit event for the current request: the actor, the chain scope and the
// source address. Action, Target and Result are filled per event by the caller.
//
// The source address comes from the one resolver that owns it (§8), never from the socket here, so
// a trusted-proxy configuration cannot be bypassed by a handler reading the wrong field. The
// timestamp is left zero on purpose: the audit writer owns the clock and truncates to microseconds,
// which is what keeps a stored row's hash equal to the one verification recomputes.
func (h *handler) newEvent(ctx context.Context) audit.Event {
	actor := reqctx.From(ctx)
	scope := actor.OrgID
	if scope == "" {
		scope = audit.PlatformScope
	}
	kind := audit.ActorUser
	switch {
	case actor.IsService():
		kind = audit.ActorService
	case actor.IsPlatform():
		kind = audit.ActorPlatform
	case actor.IsAnonymous():
		kind = audit.ActorAnonymous
	}
	id := actor.UserID
	if actor.IsService() {
		id = actor.TokenID
	}
	// The timestamp is set here rather than left zero. The audit writer truncates it to
	// microseconds, but it rejects a zero one ("field timestamp is zero"), and a rejected event
	// fails the request that produced it: a write whose audit row cannot be recorded must not
	// report success. Owning the clock here also means the event says when the handler acted.
	return audit.Event{
		Scope:     scope,
		OrgID:     actor.OrgID,
		ActorID:   id,
		ActorKind: kind,
		SourceIP:  reqctx.SourceIPFrom(ctx),
		Timestamp: time.Now().UTC(),
	}
}

// parseVersion parses a decimal version path segment. Version numbering begins at 1.
//
// The digit check is explicit because strconv.ParseInt also accepts a leading sign, so "+1" and
// "1" would otherwise both address version 1. A URL segment has one spelling for one version.
func parseVersion(raw string) (int64, bool) {
	if raw == "" {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
