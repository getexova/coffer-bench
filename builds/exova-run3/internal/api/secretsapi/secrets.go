package secretsapi

import (
	"net/http"
	"time"
	"unicode/utf8"

	"coffer/internal/audit"
	"coffer/internal/authz"
	"coffer/internal/httpx"
	"coffer/internal/store/secrets"
)

// validateValue enforces SPEC §3: a value is any UTF-8 string of 0 to 65,536 bytes inclusive.
//
// The UTF-8 check is not cosmetic. A value is returned as a JSON string, so a byte sequence that is
// not valid UTF-8 would come back as U+FFFD replacement characters and would not round-trip
// byte-exactly, which the spec requires. Rejecting it at the boundary is the only way to keep that
// promise, and it makes byte-exactness a property of the stored data rather than of the encoder.
func validateValue(v []byte) error {
	if len(v) > secrets.MaxValueBytes {
		return secrets.ErrValueTooLarge
	}
	if !utf8.Valid(v) {
		return secrets.ErrInvalidUTF8
	}
	return nil
}

// listResponse is one row of an environment listing. It carries metadata and never a value.
type listResponse struct {
	Key       string    `json:"key"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// valueResponse is a single key's value. This is a sanctioned plaintext exit.
type valueResponse struct {
	Key     string `json:"key"`
	Version int64  `json:"version"`
	Value   string `json:"value"`
}

// versionResponse is the result of a direct write.
type versionResponse struct {
	Version int64 `json:"version"`
}

// pendingResponse is the 202 body for a write to a protected environment. It is not an error.
type pendingResponse struct {
	Status   string `json:"status"`
	ChangeID string `json:"change_id"`
}

// historyResponse is one entry of a key's history, including tombstones.
type historyResponse struct {
	Version   int64     `json:"version"`
	Deleted   bool      `json:"deleted"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// list handles GET /projects/{p}/envs/{e}/secrets.
//
// A viewer may list: names and metadata are exactly what a viewer is allowed to see. The query is
// one statement that joins the current version, so the cost does not grow with the number of
// secrets, and no value is decrypted.
func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRead, authz.CanView)
	if !ok {
		return
	}
	rows, err := h.store.List(r.Context(), res.scope)
	if err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	out := make([]listResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, listResponse{
			Key:       row.Key,
			Version:   row.Version,
			UpdatedAt: row.UpdatedAt,
			UpdatedBy: row.UpdatedBy,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// get handles GET /projects/{p}/envs/{e}/secrets/{key}.
//
// A viewer gets 403: the key is visible to them, but reading its value is not a viewer capability.
// A tombstoned key is 404, identical to a key that never existed.
func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRead, authz.CanRead)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}

	val, err := h.store.Value(r.Context(), res.scope, key)
	if err != nil {
		if err == secrets.ErrNotFound {
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return
		}
		// A decryption failure lands here and becomes a 500 with no value in the body. A
		// ciphertext that was moved between rows must never be reported as a value.
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// The audit event is written before the value reaches the wire, so an unaudited read cannot
	// happen: a failed append fails the request.
	if err := secrets.AuditRead(r.Context(), h.deps.Audit, h.newEvent(r.Context()),
		res.scope.ProjectID, res.scope.EnvID, key); err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, valueResponse{Key: val.Key, Version: val.Version, Value: string(val.Value)})
}

// setRequest is the PUT body. Value is a pointer so that `{"value":""}` (a valid empty value) is
// distinguishable from a body that omits the field entirely.
type setRequest struct {
	Value           *string `json:"value"`
	ExpectedVersion *int64  `json:"expected_version"`
}

// set handles PUT /projects/{p}/envs/{e}/secrets/{key}.
//
// A writer on a protected environment does not change the value: the proposal is stored encrypted
// and the response is 202 with the change id, for owners and admins exactly as for anyone else who
// can write (§2.8).
func (h *handler) set(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretWrite, authz.CanWrite)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}
	var req setRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.Value == nil {
		httpx.WriteError(w, r, httpx.Validation(msgBadValue))
		return
	}
	value := []byte(*req.Value)
	if err := validateValue(value); err != nil {
		httpx.WriteError(w, r, httpx.Validation(msgBadValue))
		return
	}
	if req.ExpectedVersion != nil && *req.ExpectedVersion < 0 {
		httpx.WriteError(w, r, httpx.Validation(msgBadVersion))
		return
	}

	h.write(w, r, res, secrets.WriteRequest{
		Scope:           res.scope,
		Key:             key,
		Op:              secrets.OpSet,
		Value:           value,
		ExpectedVersion: req.ExpectedVersion,
		Actor:           actorRef(res.actor),
	}, secrets.Proposal{
		Scope:    res.scope,
		Key:      key,
		Op:       secrets.OpSet,
		Value:    value,
		Proposer: actorRef(res.actor),
	})
}

// remove handles DELETE /projects/{p}/envs/{e}/secrets/{key}.
//
// A delete writes a tombstone version, so the history keeps the fact that the key existed. It does
// not remove the row, and it never removes the versions.
func (h *handler) remove(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretDelete, authz.CanWrite)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}
	h.write(w, r, res, secrets.WriteRequest{
		Scope: res.scope,
		Key:   key,
		Op:    secrets.OpDelete,
		Actor: actorRef(res.actor),
	}, secrets.Proposal{
		Scope:    res.scope,
		Key:      key,
		Op:       secrets.OpDelete,
		Proposer: actorRef(res.actor),
	})
}

// history handles GET /projects/{p}/envs/{e}/secrets/{key}/versions.
//
// History is metadata, so a viewer may read it. Tombstones appear with deleted:true and no value.
func (h *handler) history(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRead, authz.CanView)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}
	rows, err := h.store.History(r.Context(), res.scope, key)
	if err != nil {
		if err == secrets.ErrNotFound {
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return
		}
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	out := make([]historyResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, historyResponse{
			Version:   row.Version,
			Deleted:   row.Deleted,
			CreatedAt: row.CreatedAt,
			CreatedBy: row.CreatedBy,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// versionAt handles GET /projects/{p}/envs/{e}/secrets/{key}/versions/{n}.
//
// This is a sanctioned value exit: it is audited with one secret.read, exactly like a current get.
func (h *handler) versionAt(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRead, authz.CanRead)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}
	version, ok := parseVersion(r.PathValue("n"))
	if !ok {
		httpx.WriteError(w, r, httpx.Validation(msgBadVersion))
		return
	}

	val, err := h.store.ValueAt(r.Context(), res.scope, key, version)
	if err != nil {
		if err == secrets.ErrNotFound {
			httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
			return
		}
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := secrets.AuditRead(r.Context(), h.deps.Audit, h.newEvent(r.Context()),
		res.scope.ProjectID, res.scope.EnvID, key); err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, valueResponse{Key: val.Key, Version: val.Version, Value: string(val.Value)})
}

// rollbackRequest is the POST body for a rollback.
type rollbackRequest struct {
	To int64 `json:"to"`
}

// rollback handles POST /projects/{p}/envs/{e}/secrets/{key}/rollback.
//
// Rolling back creates a new version holding the old value; it does not resurrect the old version
// number, so the history stays append-only and a later get sees the newest version.
func (h *handler) rollback(w http.ResponseWriter, r *http.Request) {
	if !h.gateMustChangePassword(w, r) {
		return
	}
	res, ok := h.resolveScope(w, r, audit.ActionSecretRollback, authz.CanWrite)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !secrets.ValidKey(key) {
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
		return
	}
	var req rollbackRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.To < 1 {
		httpx.WriteError(w, r, httpx.Validation(msgBadVersion))
		return
	}
	h.write(w, r, res, secrets.WriteRequest{
		Scope:         res.scope,
		Key:           key,
		Op:            secrets.OpRollback,
		TargetVersion: req.To,
		Actor:         actorRef(res.actor),
	}, secrets.Proposal{
		Scope:     res.scope,
		Key:       key,
		Op:        secrets.OpRollback,
		TargetVer: req.To,
		Proposer:  actorRef(res.actor),
	})
}

// write is the single path a mutation takes. It decides between applying the change and proposing
// it, so the protected-environment rule cannot be missed by one of the three write handlers.
//
// On a protected environment the live version is read first and recorded as base_version: the
// version the proposer saw. Approval compares it with the version that is current at approval time,
// which is how a change made in between is detected as stale.
func (h *handler) write(w http.ResponseWriter, r *http.Request, res resolved, wr secrets.WriteRequest, prop secrets.Proposal) {
	ctx := r.Context()

	if !res.scope.Protected {
		applied, err := h.store.ApplyAudited(ctx, wr, h.deps.Audit, h.newEvent(ctx))
		if err != nil {
			h.writeStoreError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, versionResponse{Version: applied.Version})
		return
	}

	baseVersion, _, _, err := h.store.CurrentVersion(ctx, res.scope, wr.Key)
	if err != nil {
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	prop.BaseVer = baseVersion

	// A change request records a human proposer, because change_requests.proposer_id references
	// users and because the two-person rule needs a person who can be told apart from the approver.
	// A service token has no users row, so its proposal is attributed to the user who issued the
	// token. The audit event is built separately and still names the token: the log records what
	// actually acted, while the request records who is accountable for it.
	if res.actor.IsService() {
		issuer, err := h.store.ServiceTokenCreator(ctx, res.actor.TokenID)
		if err != nil {
			if err == secrets.ErrProposerUnavailable {
				h.deny(ctx, res.actor, audit.ActionChangeCreated, target(res.project, res.env, wr.Key))
				httpx.WriteError(w, r, httpx.Forbidden(msgForbidden))
				return
			}
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
		prop.Proposer = secrets.ActorRef{ID: issuer, Kind: string(audit.ActorUser)}
	}

	ch, err := h.store.CreateChangeAudited(ctx, prop, h.deps.Audit, h.newEvent(ctx))
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, pendingResponse{Status: secrets.StatusPending, ChangeID: ch.ID})
}

// writeStoreError maps a storage error to its status. Every branch is deliberate: this is the only
// place a storage outcome becomes an HTTP status for a mutation.
func (h *handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case err == secrets.ErrNotFound:
		httpx.WriteError(w, r, httpx.NotFound(msgNotFound))
	case err == secrets.ErrConflict:
		httpx.WriteError(w, r, httpx.Conflict(msgConflict))
	case err == secrets.ErrInvalidKey:
		httpx.WriteError(w, r, httpx.Validation(msgBadKey))
	case err == secrets.ErrInvalidUTF8, err == secrets.ErrValueTooLarge:
		httpx.WriteError(w, r, httpx.Validation(msgBadValue))
	default:
		httpx.WriteError(w, r, httpx.Internal(err))
	}
}
