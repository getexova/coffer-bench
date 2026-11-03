package authapi

import (
	"errors"

	"net/http"

	"coffer/internal/audit"
	"coffer/internal/httpx"
	"coffer/internal/idgen"
	"coffer/internal/reqctx"
	authstore "coffer/internal/store/auth"
)

// orgScope resolves the caller for an organization-scoped route.
//
// The platform admin is answered with 404 here rather than 403, because every
// organization-scoped route is outside its reach and SPEC §2.10 requires that to be
// indistinguishable from a route it cannot see at all. A service token reaches this
// point with a real organization, so it is refused later with 403 where the rule
// says so.
func (a *api) orgScope(w http.ResponseWriter, r *http.Request, target string) (reqctx.Actor, bool) {
	actor, ok := a.requireActor(w, r)
	if !ok {
		return actor, false
	}
	if actor.IsPlatform() {
		a.hide(w, r, target)
		return actor, false
	}
	return actor, true
}

// requireManager enforces that the caller may manage members, grants and tokens:
// owners and admins may, members and service tokens may not (SPEC §2.3, §2.6, §2.7).
//
// It runs before any field is validated, which is what makes a plain member calling
// these routes get 403 rather than a 400 that would describe the payload.

// requireManager enforces that the caller may manage members, grants and tokens:
// owners and admins may, members and service tokens may not (SPEC §2.3, §2.6, §2.7).
//
// It runs before any field is validated, which is what makes a plain member calling
// these routes get 403 rather than a 400 that would describe the payload.
func (a *api) requireManager(w http.ResponseWriter, r *http.Request, actor reqctx.Actor, target string) bool {
	if actor.IsService() {
		a.deny(w, r, target)
		return false
	}
	switch actor.Role {
	case reqctx.RoleOwner, reqctx.RoleAdmin:
		return true
	default:
		a.deny(w, r, target)
		return false
	}
}

// handleListMembers implements GET /api/v1/members.

type memberView struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
}

// handleListMembers implements GET /api/v1/members.
func (a *api) handleListMembers(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "members")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "members") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	members, err := authstore.ListMembers(r.Context(), conn, actor.OrgID)
	if err != nil {
		a.logger().Error("members: list", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	out := make([]memberView, 0, len(members))
	for _, m := range members {
		out = append(out, memberView{
			ID:                 m.ID,
			Email:              m.Email,
			Role:               m.Role,
			MustChangePassword: m.MustChangePassword,
			CreatedAt:          timeString(m.CreatedAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": out})
}

// handleCreateMember implements POST /api/v1/members.
//
// The new account starts with must_change_password set: the admin chose that
// password, not the person who has to use it, so the first thing that person must do
// is replace it (SPEC §4 P1(a)).

// handleCreateMember implements POST /api/v1/members.
//
// The new account starts with must_change_password set: the admin chose that
// password, not the person who has to use it, so the first thing that person must do
// is replace it (SPEC §4 P1(a)).
func (a *api) handleCreateMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "members")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "members") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	var req struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	// Authorization before validation: an admin may not create an owner, and that
	// refusal must not depend on the rest of the payload being well formed.
	if req.Role == reqctx.RoleOwner && actor.Role != reqctx.RoleOwner {
		a.deny(w, r, "members")
		return
	}
	if err := validateRole(req.Role); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	email := authstore.NormalizeEmail(req.Email)
	if err := validateEmail(email); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	if err := validatePassword(req.Password); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		a.logger().Error("members: hash password", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	user := authstore.User{
		ID:                 idgen.New("usr_"),
		OrgID:              actor.OrgID,
		Email:              email,
		PasswordHash:       hash,
		Role:               req.Role,
		MustChangePassword: true,
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("members: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	created, err := authstore.CreateUser(r.Context(), tx, user)
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			// Generic on purpose: no organization name, no "already in org X".
			httpx.WriteError(w, r, httpx.Conflict("a user with that email already exists"))
			return
		}
		a.logger().Error("members: create", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionMemberAdded, "user/"+created.ID, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("members: audit member.added", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("members: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"member": memberView{
			ID:                 created.ID,
			Email:              created.Email,
			Role:               created.Role,
			MustChangePassword: true,
			CreatedAt:          timeString(created.CreatedAt),
		},
	})
}

// handleUpdateMember implements PATCH /api/v1/members/{user_id} {role}.
//
// The check order is the one SPEC §2.12 and §2.2 require, and it is not
// interchangeable:
//
//	401  no credential
//	404  platform admin, or a user id that is not in this organization
//	403  caller is not an owner or admin, or is an admin reaching an owner, or is
//	     an admin trying to create an owner
//	409  the target is the last owner (before the self check, so the last owner gets
//	     409 for demoting themselves rather than 400)
//	400  the caller is changing their own role, or the role is not a known role

// handleUpdateMember implements PATCH /api/v1/members/{user_id} {role}.
//
// The check order is the one SPEC §2.12 and §2.2 require, and it is not
// interchangeable:
//
//	401  no credential
//	404  platform admin, or a user id that is not in this organization
//	403  caller is not an owner or admin, or is an admin reaching an owner, or is
//	     an admin trying to create an owner
//	409  the target is the last owner (before the self check, so the last owner gets
//	     409 for demoting themselves rather than 400)
//	400  the caller is changing their own role, or the role is not a known role
func (a *api) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "members")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "members") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	userID := r.PathValue("user_id")
	var req struct {
		Role string `json:"role"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("members: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, err := authstore.UserByIDInOrg(r.Context(), tx, actor.OrgID, userID)
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "members")
			return
		}
		a.logger().Error("members: load target", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// Check order, fixed by SPEC §2.2/§2.12 and the CTO's ruling, and not
	// interchangeable:
	//
	//	1. the target is a live member of this organization      -> 404 if not
	//	2. only an owner may touch or create an owner            -> 403
	//	3. the last owner cannot be demoted (owner callers only) -> 409
	//	4. a caller never changes their own role                 -> 400
	//	5. the role must be a known role                         -> 400
	//
	// Authorization comes FIRST. The owner-permission gate precedes the last-owner
	// gate, because otherwise an admin demoting the sole owner gets 409 while an
	// admin demoting a non-last owner gets 403 — and that difference tells the admin
	// how many owners exist. An admin is never permitted to touch an owner, so an
	// admin gets 403 in both cases. 409 is reserved for an OWNER acting on the last
	// owner, which is the only caller that could actually perform the demotion.
	//
	// The self-change rule stays after both, so a sole owner demoting themselves
	// still gets 409 (the thing that is actually wrong) and a non-sole self-change
	// gets 400.
	//
	// The owner rows are locked first so two concurrent demotions of the last two
	// owners cannot both observe two.
	ownerIDs, err := authstore.LockOwners(r.Context(), tx, actor.OrgID)
	if err != nil {
		a.logger().Error("members: lock owners", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// Only an owner may touch an owner, and only an owner may create one.
	if actor.Role != reqctx.RoleOwner {
		if target.Role == reqctx.RoleOwner || req.Role == reqctx.RoleOwner {
			a.deny(w, r, "members")
			return
		}
	}

	if target.Role == reqctx.RoleOwner && req.Role != reqctx.RoleOwner && len(ownerIDs) <= 1 {
		httpx.WriteError(w, r, httpx.Conflict("the last owner cannot be demoted"))
		return
	}

	// No self-escalation and no self-demotion: a caller never changes their own role
	// (SPEC §2.12). Never applied, never a 200.
	if target.ID == actor.UserID {
		httpx.WriteError(w, r, httpx.Validation("you cannot change your own role"))
		return
	}

	if err := validateRole(req.Role); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	changed, err := authstore.UpdateUserRole(r.Context(), tx, actor.OrgID, target.ID, req.Role)
	if err != nil {
		a.logger().Error("members: update role", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if !changed {
		a.hide(w, r, "members")
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionMemberRoleChanged, "user/"+target.ID, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("members: audit member.role_changed", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("members: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	target.Role = req.Role
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"member": memberView{
			ID:                 target.ID,
			Email:              target.Email,
			Role:               target.Role,
			MustChangePassword: target.MustChangePassword,
			CreatedAt:          timeString(target.CreatedAt),
		},
	})
}

// handleRemoveMember implements DELETE /api/v1/members/{user_id}.
//
// Removal is a soft delete. The next request made with any of that user's tokens
// fails, because token resolution rejects users.removed_at in SQL (SPEC §2.11).

// handleRemoveMember implements DELETE /api/v1/members/{user_id}.
//
// Removal is a soft delete. The next request made with any of that user's tokens
// fails, because token resolution rejects users.removed_at in SQL (SPEC §2.11).
func (a *api) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "members")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "members") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("members: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, err := authstore.UserByIDInOrg(r.Context(), tx, actor.OrgID, r.PathValue("user_id"))
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "members")
			return
		}
		a.logger().Error("members: load target", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	if target.Role == reqctx.RoleOwner && actor.Role != reqctx.RoleOwner {
		a.deny(w, r, "members")
		return
	}

	ownerIDs, err := authstore.LockOwners(r.Context(), tx, actor.OrgID)
	if err != nil {
		a.logger().Error("members: lock owners", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if target.Role == reqctx.RoleOwner && len(ownerIDs) <= 1 {
		httpx.WriteError(w, r, httpx.Conflict("the last owner cannot be removed"))
		return
	}

	// A caller never changes their own access, and removing the account a request is
	// authenticated with is exactly that. Checked after the last-owner rule so the
	// sole owner gets 409 for the thing that is actually wrong.
	if target.ID == actor.UserID {
		httpx.WriteError(w, r, httpx.Validation("you cannot remove your own account"))
		return
	}

	removed, err := authstore.RemoveUser(r.Context(), tx, actor.OrgID, target.ID)
	if err != nil {
		a.logger().Error("members: remove", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if !removed {
		a.hide(w, r, "members")
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionMemberRemoved, "user/"+target.ID, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("members: audit member.removed", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("members: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

// handleSetGrant implements PUT /api/v1/members/{user_id}/grants/{project} {level}.
//
// Visibility is settled before the payload is looked at: the target user must be a
// live member of this organization (404 otherwise) and the project must exist in it
// (404 otherwise), and only then does the level get validated.

// handleSetGrant implements PUT /api/v1/members/{user_id}/grants/{project} {level}.
//
// Visibility is settled before the payload is looked at: the target user must be a
// live member of this organization (404 otherwise) and the project must exist in it
// (404 otherwise), and only then does the level get validated.
func (a *api) handleSetGrant(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "grants")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "grants") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("grants: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, ok := a.grantTarget(w, r, tx, actor)
	if !ok {
		return
	}
	project, ok := a.grantProject(w, r, tx, actor)
	if !ok {
		return
	}

	// A caller never changes their own grants, up or down (SPEC §2.12).
	if target.ID == actor.UserID {
		httpx.WriteError(w, r, httpx.Validation("you cannot change your own grants"))
		return
	}
	if err := validateLevel(req.Level); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	if err := authstore.SetGrant(r.Context(), tx, project.ID, target.ID, req.Level); err != nil {
		a.logger().Error("grants: set", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionGrantSet,
		"project/"+project.Slug+"/grant/"+target.ID, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("grants: audit grant.set", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("grants: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"grant": map[string]any{
			"user_id": target.ID,
			"project": project.Slug,
			"level":   req.Level,
		},
	})
}

// handleRevokeGrant implements DELETE /api/v1/members/{user_id}/grants/{project}.
//
// Revoking a grant that does not exist is idempotent: 200 with revoked=false. The
// project and the member must still be visible, so the route cannot be used to
// discover whether a project exists in another organization.

// handleRevokeGrant implements DELETE /api/v1/members/{user_id}/grants/{project}.
//
// Revoking a grant that does not exist is idempotent: 200 with revoked=false. The
// project and the member must still be visible, so the route cannot be used to
// discover whether a project exists in another organization.
func (a *api) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "grants")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "grants") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("grants: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	target, ok := a.grantTarget(w, r, tx, actor)
	if !ok {
		return
	}
	project, ok := a.grantProject(w, r, tx, actor)
	if !ok {
		return
	}

	if target.ID == actor.UserID {
		httpx.WriteError(w, r, httpx.Validation("you cannot change your own grants"))
		return
	}

	removed, err := authstore.DeleteGrant(r.Context(), tx, project.ID, target.ID)
	if err != nil {
		a.logger().Error("grants: revoke", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if removed {
		ev := a.auditEvent(r.Context(), actor, audit.ActionGrantRevoked,
			"project/"+project.Slug+"/grant/"+target.ID, audit.ResultSuccess)
		if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
			a.logger().Error("grants: audit grant.revoked", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("grants: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"revoked": removed})
}

// grantTarget resolves the {user_id} path parameter to a live member of the
// caller's organization, answering 404 when it is not one. An admin may not grant
// to an owner, so that case is refused with 403 once the target is known to be
// visible.

// grantTarget resolves the {user_id} path parameter to a live member of the
// caller's organization, answering 404 when it is not one. An admin may not grant
// to an owner, so that case is refused with 403 once the target is known to be
// visible.
func (a *api) grantTarget(w http.ResponseWriter, r *http.Request, q authstore.Querier, actor reqctx.Actor) (authstore.User, bool) {
	target, err := authstore.UserByIDInOrg(r.Context(), q, actor.OrgID, r.PathValue("user_id"))
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "grants")
			return authstore.User{}, false
		}
		a.logger().Error("grants: load target", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return authstore.User{}, false
	}
	if target.Role == reqctx.RoleOwner && actor.Role != reqctx.RoleOwner {
		// Owners need no grant; an admin may not touch an owner's access at all.
		a.deny(w, r, "grants")
		return authstore.User{}, false
	}
	return target, true
}

// grantProject resolves the {project} path parameter inside the caller's
// organization, answering the invisible-resource 404 when it is not there.

// grantProject resolves the {project} path parameter inside the caller's
// organization, answering the invisible-resource 404 when it is not there.
func (a *api) grantProject(w http.ResponseWriter, r *http.Request, q authstore.Querier, actor reqctx.Actor) (authstore.Project, bool) {
	project, err := authstore.ProjectBySlug(r.Context(), q, actor.OrgID, r.PathValue("project"))
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "grants")
			return authstore.Project{}, false
		}
		a.logger().Error("grants: load project", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return authstore.Project{}, false
	}
	return project, true
}
