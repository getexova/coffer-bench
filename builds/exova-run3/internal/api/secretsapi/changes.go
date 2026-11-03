package secretsapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/audit"
	"coffer/internal/authz"
	"coffer/internal/httpx"
	"coffer/internal/reqctx"
	"coffer/internal/store/secrets"
)

// changeResponse is one change request in a listing.
//
// It never carries the proposed value. A pending value is ciphertext at rest, and an approver who
// wants to see what they are approving reads it through the sanctioned exits after it is applied —
// or from the proposal's own description, which is the operation and the key. Returning the value
// here would make the change list a fourth plaintext exit that nobody audits per key.
type changeResponse struct {
	ID            string     `json:"id"`
	Project       string     `json:"project"`
	Env           string     `json:"env"`
	Key           string     `json:"key"`
	Op            string     `json:"op"`
	BaseVersion   int64      `json:"base_version"`
	TargetVersion *int64     `json:"target_version,omitempty"`
	Status        string     `json:"status"`
	ProposerID    string     `json:"proposer_id"`
	CreatedAt     time.Time  `json:"created_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	ResolverID    string     `json:"resolver_id,omitempty"`
}

func changeView(ch secrets.Change) changeResponse {
	return changeResponse{
		ID:            ch.ID,
		Project:       ch.ProjectSlug,
		Env:           ch.EnvSlug,
		Key:           ch.Key,
		Op:            string(ch.Op),
		BaseVersion:   ch.BaseVersion,
		TargetVersion: ch.TargetVersion,
		Status:        ch.Status,
		ProposerID:    ch.ProposerID,
		CreatedAt:     ch.CreatedAt,
		ResolvedAt:    ch.ResolvedAt,
		ResolverID:    ch.ResolverID,
	}
}

// resolvedChangeResponse is the 200 body for approve and reject.
type resolvedChangeResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Key     string `json:"key"`
	Version int64  `json:"version,omitempty"`
}

// listChanges handles GET /changes?status=.
//
// Visibility follows project grants: an owner or admin sees every change in the organization, and a
// member sees only changes in projects they have a grant for. A member without a grant sees nothing
// rather than a 404, because the route itself is theirs — the individual changes are not.
func (h *handler) listChanges(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	ctx := r.Context()
	actor := reqctx.From(ctx)

	// A service token has no change requests: it is confined to secret operations in its scope
	// (§2.7) and can never approve one.
	if actor.IsService() {
		h.deny(ctx, actor, audit.ActionDenied, "changes")
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
		return
	}
	if actor.OrgID == "" {
		h.deny(ctx, actor, audit.ActionDenied, "changes")
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
		return
	}

	status := r.URL.Query().Get("status")
	if status != "" && !secrets.ValidStatus(status) {
		httpx.WriteError(w, r, httpx.Validation(msgBadStatus))
		return
	}

	changes, err := h.store.ListChanges(ctx, actor.OrgID, status, 500)
	if err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	var grants map[string]string
	manager := authz.IsOrgManager(actor)
	if !manager {
		grants, err = h.store.GrantsFor(ctx, actor.OrgID, actor.UserID)
		if err != nil {
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
	}

	out := make([]changeResponse, 0, len(changes))
	for _, ch := range changes {
		if !manager {
			if _, ok := grants[ch.ProjectID]; !ok {
				continue // no grant on this project: the change is invisible
			}
		}
		out = append(out, changeView(ch))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// loadChangeForResolution loads a change and enforces the two checks that come before any state
// change: the caller must be able to see the change's project, and must be an owner or an admin.
//
// Self-approval is checked inside the transaction, immediately before the compare-and-swap, so a
// self-approval cannot consume the request even in a race.
func (h *handler) loadChangeForResolution(w http.ResponseWriter, r *http.Request) (secrets.Change, bool) {
	ctx := r.Context()
	actor := reqctx.From(ctx)

	// A service token can never approve or reject a change, whatever its access mode (§2.7).
	if actor.IsService() {
		h.deny(ctx, actor, audit.ActionDenied, "change/"+r.PathValue("id"))
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
		return secrets.Change{}, false
	}
	if actor.OrgID == "" {
		h.deny(ctx, actor, audit.ActionDenied, "change/"+r.PathValue("id"))
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
		return secrets.Change{}, false
	}

	ch, err := h.store.GetChange(ctx, actor.OrgID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			h.deny(ctx, actor, audit.ActionDenied, "change/"+r.PathValue("id"))
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return secrets.Change{}, false
		}
		httpx.WriteError(w, r, httpx.Internal(err))
		return secrets.Change{}, false
	}

	// Visibility of the project the change targets. A member with no grant on it cannot see the
	// change at all, which is a 404 for the same reason the project is one.
	if !authz.IsOrgManager(actor) {
		grants, err := h.store.GrantsFor(ctx, actor.OrgID, actor.UserID)
		if err != nil {
			httpx.WriteError(w, r, httpx.Internal(err))
			return secrets.Change{}, false
		}
		if _, ok := grants[ch.ProjectID]; !ok {
			h.deny(ctx, actor, audit.ActionDenied, "change/"+ch.ID)
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return secrets.Change{}, false
		}
	}

	// Approver authority. A member who can see the change but may not resolve it gets 403: the
	// resource is visible, the permission is not.
	if !authz.CanApprove(actor) {
		h.deny(ctx, actor, audit.ActionDenied, "change/"+ch.ID)
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
		return secrets.Change{}, false
	}

	return ch, true
}

// approve handles POST /changes/{id}/approve.
//
// The whole resolution is one transaction. The self-approval check, the compare-and-swap on status,
// the locked version comparison, the apply and both audit events either all happen or none do.
//
// The stale case is the one that needs care: marking the request stale is a state change that must
// survive the 409 we return, so the transaction commits on that specific outcome and rolls back on
// every other error.
func (h *handler) approve(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	ch, ok := h.loadChangeForResolution(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor := reqctx.From(ctx)
	ref := actorRef(actor)
	ev := h.newEvent(ctx)

	var applied secrets.Applied
	err := h.store.InTxWithCommit(ctx, secrets.ErrStale, func(tx pgx.Tx) error {
		var err error
		applied, err = h.store.ApproveTx(ctx, tx, ch, ref, authz.CanApprove(actor), h.deps.Audit, ev)
		return err
	})
	if err != nil {
		h.writeChangeError(w, r, ch, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resolvedChangeResponse{
		ID:      ch.ID,
		Status:  secrets.StatusApproved,
		Key:     ch.Key,
		Version: applied.Version,
	})
}

// reject handles POST /changes/{id}/reject.
//
// Rejecting a request that is no longer pending is 409, decided by the same conditional update that
// makes double approval impossible.
func (h *handler) reject(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	ch, ok := h.loadChangeForResolution(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor := reqctx.From(ctx)
	ref := actorRef(actor)
	ev := h.newEvent(ctx)

	err := h.store.InTx(ctx, func(tx pgx.Tx) error {
		return h.store.RejectTx(ctx, tx, ch, ref, h.deps.Audit, ev)
	})
	if err != nil {
		h.writeChangeError(w, r, ch, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resolvedChangeResponse{
		ID:     ch.ID,
		Status: secrets.StatusRejected,
		Key:    ch.Key,
	})
}

// writeChangeError maps a change-resolution error to its status. The four outcomes are distinct on
// purpose: they tell a caller whether to propose again (stale), give up (resolved), or ask someone
// else (self-approval, not an approver).
func (h *handler) writeChangeError(w http.ResponseWriter, r *http.Request, ch secrets.Change, err error) {
	switch {
	case errors.Is(err, secrets.ErrSelfApproval):
		// A 403, and no state change: the request is still pending for someone else.
		h.deny(r.Context(), reqctx.From(r.Context()), audit.ActionChangeApproved, "change/"+ch.ID)
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
	case errors.Is(err, secrets.ErrNotApprover):
		h.deny(r.Context(), reqctx.From(r.Context()), audit.ActionChangeApproved, "change/"+ch.ID)
		httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
	case errors.Is(err, secrets.ErrAlreadyResolved):
		httpx.WriteError(w, r, httpx.Conflict(msgResolved))
	case errors.Is(err, secrets.ErrStale):
		httpx.WriteError(w, r, httpx.Conflict(msgStale))
	case errors.Is(err, secrets.ErrNotFound):
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
	case errors.Is(err, secrets.ErrConflict):
		httpx.WriteError(w, r, httpx.Conflict(msgConflict))
	default:
		httpx.WriteError(w, r, httpx.Internal(err))
	}
}
