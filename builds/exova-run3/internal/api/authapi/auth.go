package authapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"net/http"

	"coffer/internal/audit"
	"coffer/internal/httpx"
	"coffer/internal/idgen"
	"coffer/internal/reqctx"
	authstore "coffer/internal/store/auth"
)

// NewAuthenticator returns the reqctx.Authenticator that middleware calls once per
// request. It is the only place a bearer token is turned into an actor.
func NewAuthenticator(deps Deps) reqctx.Authenticator {
	return &authenticator{deps: deps}
}

type authenticator struct {
	deps Deps
}

// Authenticate resolves a token to an actor in exactly one indexed statement.
//
// Everything that makes revocation immediate is in that statement
// (authstore.ResolveTokenSQL): revoked tokens, expired service tokens compared
// against the database clock, removed users and disabled organizations are all
// rejected by SQL predicates, so there is no cached decision that could outlive
// them.

// Authenticate resolves a token to an actor in exactly one indexed statement.
//
// Everything that makes revocation immediate is in that statement
// (authstore.ResolveTokenSQL): revoked tokens, expired service tokens compared
// against the database clock, removed users and disabled organizations are all
// rejected by SQL predicates, so there is no cached decision that could outlive
// them.
// Authenticate resolves a token to an actor, discarding the must-change flag. It
// exists for the frozen reqctx.Authenticator interface; Resolve is the method that
// carries the flag, and middleware prefers it.
func (a *authenticator) Authenticate(ctx context.Context, token string) (reqctx.Actor, error) {
	actor, _, err := a.Resolve(ctx, token)
	return actor, err
}

// Resolve resolves a token to an actor and the must-change-password flag from the same
// row, in one statement.
//
// The flag is a return value rather than stored state, so there is no cache to miss
// and no eviction that could admit a gated caller. It is read from the credential that
// was just proven live, which also means a password change takes effect on the very
// next request with no invalidation step.
func (a *authenticator) Resolve(ctx context.Context, token string) (reqctx.Actor, bool, error) {
	conn := a.deps.conn()
	if conn == nil {
		return reqctx.Actor{}, false, errors.New("authapi: no database configured")
	}
	if !looksLikeToken(token) {
		// Wrong prefix or impossible length: no query, same answer.
		return reqctx.Actor{}, false, fmt.Errorf("%w: malformed credential", reqctx.ErrUnauthenticated)
	}

	resolved, err := authstore.ResolveToken(ctx, conn, authstore.HashToken(token))
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			return reqctx.Actor{}, false, fmt.Errorf("%w: credential did not resolve", reqctx.ErrUnauthenticated)
		}
		// A database failure is not an authentication failure: the caller is not
		// told 401 for our outage, and the error carries no credential.
		return reqctx.Actor{}, false, fmt.Errorf("authapi: resolve credential: %w", err)
	}

	actor := reqctx.Actor{
		TokenID: resolved.TokenID,
		Email:   resolved.Email,
		OrgID:   resolved.OrgID,
		Role:    resolved.Role,
	}
	switch resolved.Kind {
	case authstore.KindService:
		actor.Kind = reqctx.KindService
		actor.ProjectID = resolved.ProjectID
		actor.EnvID = resolved.EnvID
		actor.Access = reqctx.Access(resolved.Access)
	case authstore.KindUser:
		actor.UserID = resolved.UserID
		if resolved.Role == reqctx.RolePlatformAdmin || resolved.OrgID == "" {
			// The platform admin belongs to no organization. Its role is the only
			// role with no org scope, and every organization-scoped route answers
			// it with the same 404 a missing resource gets.
			actor.Kind = reqctx.KindPlatform
			actor.Role = reqctx.RolePlatformAdmin
		} else {
			actor.Kind = reqctx.KindUser
		}
	default:
		return reqctx.Actor{}, false, fmt.Errorf("%w: unknown credential kind", reqctx.ErrUnauthenticated)
	}

	// The flag the resolution query already loaded travels back with the actor, for
	// the middleware to set on the context. Service tokens carry no user, so the
	// column is false for them and they are never gated.
	mustChange := resolved.Kind == authstore.KindUser && resolved.MustChangePassword
	return actor, mustChange, nil
}

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

// Bootstrap creates the platform admin on first boot, and only then: if any user
// exists it does nothing. It is called after migrations and before the listener
// starts, and it is safe to call on every boot.
//
// The platform admin is the one account created with must_change_password = false:
// the operator supplies that password from their own environment, so nobody else
// chose it, and gating it would deadlock the first run of every automated flow.
// Every account whose password is supplied by a DIFFERENT principal — a member
// added by an admin, an owner created by the platform admin — is gated.
func Bootstrap(ctx context.Context, deps Deps) error {
	conn := deps.conn()
	if conn == nil {
		return errors.New("authapi: Bootstrap requires a database")
	}
	if deps.Config == nil {
		return errors.New("authapi: Bootstrap requires config")
	}

	count, err := authstore.CountUsers(ctx, conn)
	if err != nil {
		return fmt.Errorf("authapi: count users: %w", err)
	}
	if count > 0 {
		return nil
	}

	email := authstore.NormalizeEmail(deps.Config.BootstrapAdminEmail)
	password := deps.Config.BootstrapAdminPassword
	if err := validateEmail(email); err != nil {
		return fmt.Errorf("COFFER_BOOTSTRAP_ADMIN_EMAIL: %w", err)
	}
	if err := validatePassword(password); err != nil {
		return fmt.Errorf("COFFER_BOOTSTRAP_ADMIN_PASSWORD: %w", err)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("authapi: hash bootstrap password: %w", err)
	}

	user := authstore.User{
		ID:                 idgen.New("usr_"),
		OrgID:              "",
		Email:              email,
		PasswordHash:       hash,
		Role:               reqctx.RolePlatformAdmin,
		MustChangePassword: false,
	}
	if _, err := authstore.CreateUser(ctx, conn, user); err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			// Another process bootstrapped between the count and the insert. That
			// is the outcome we wanted, not an error.
			return nil
		}
		return fmt.Errorf("authapi: create platform admin: %w", err)
	}

	deps.logger().Info("bootstrap: created the platform admin", "email", user.Email)
	return nil
}

type orgView struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

type userView struct {
	ID                 string   `json:"id"`
	Email              string   `json:"email"`
	Role               string   `json:"role"`
	MustChangePassword bool     `json:"must_change_password"`
	Organization       *orgView `json:"organization"`
}

type loginResponse struct {
	Token string   `json:"token"`
	User  userView `json:"user"`
}

// timeString renders a timestamp in the canonical audit form, which is also the
// form the CLI parses. UTC, microseconds, always present.
func timeString(t time.Time) string { return audit.FormatTimestamp(t) }

// nowUTC is the single place this slice takes a wall-clock reading for an event.

// nowUTC is the single place this slice takes a wall-clock reading for an event.
func nowUTC() time.Time { return time.Now().UTC() }

func timeStringPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := timeString(*t)
	return &s
}

func orgViewOf(org authstore.Org) *orgView {
	return &orgView{ID: org.ID, Slug: org.Slug}
}

// handleLogin implements POST /api/v1/auth/token.
//
// Three things here are security-critical and are easy to lose in a refactor:
//
//  1. An unknown email and a wrong password are the same 401 with the same body,
//     and the unknown-email path still runs a full argon2id verification against a
//     fixed dummy hash, so the two take the same time.
//  2. The lockout is checked BEFORE the password is verified, which is what makes
//     "further logins return 429 until the window passes, even with the correct
//     password" true.
//  3. The plaintext token is returned exactly once and only its SHA-256 hex is
//     stored.

// handleLogin implements POST /api/v1/auth/token.
//
// Three things here are security-critical and are easy to lose in a refactor:
//
//  1. An unknown email and a wrong password are the same 401 with the same body,
//     and the unknown-email path still runs a full argon2id verification against a
//     fixed dummy hash, so the two take the same time.
//  2. The lockout is checked BEFORE the password is verified, which is what makes
//     "further logins return 429 until the window passes, even with the correct
//     password" true.
//  3. The plaintext token is returned exactly once and only its SHA-256 hex is
//     stored.
func (a *api) handleLogin(w http.ResponseWriter, r *http.Request) {
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	now := time.Now()
	email := authstore.NormalizeEmail(req.Email)
	if email == "" {
		httpx.WriteError(w, r, httpx.Validation("email is required"))
		return
	}

	// The per-IP bucket is checked before any password work, so a spray from one
	// address cannot make the server hash passwords for free.
	sourceIP := a.sourceIP(r)
	if !a.limits.loginIP.allow(sourceIP, now) {
		writeRetryAfter(w, r, time.Second)
		httpx.WriteError(w, r, httpx.RateLimited("too many login attempts"))
		return
	}

	// The per-account lockout, before verification: five failures inside fifteen
	// minutes lock the account even for the right password.
	if locked, wait := a.limits.lockout.locked(email, now); locked {
		writeRetryAfter(w, r, wait)
		httpx.WriteError(w, r, httpx.RateLimited("account is locked, try again later"))
		return
	}

	user, err := authstore.UserByEmail(r.Context(), conn, email)
	unknown := errors.Is(err, authstore.ErrNotFound)
	if err != nil && !unknown {
		a.logger().Error("login: lookup user", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// Verify against the stored hash, or against the dummy hash when the account
	// does not exist. Same work either way.
	storedHash := user.PasswordHash
	if unknown {
		storedHash = dummyHash
	}
	ok, verifyErr := VerifyPassword(storedHash, req.Password)
	if verifyErr != nil {
		// A stored hash this package cannot parse is a server fault. It is logged
		// and answered exactly like a wrong password, so it cannot be used as an
		// account-existence oracle.
		a.logger().Error("login: stored password hash is not valid argon2id", "user_id", user.ID)
		ok = false
	}
	if unknown {
		ok = false
	}

	// A disabled organization fails authentication (docs/CONTRACTS.md §2), and it
	// must look exactly like a wrong password: same status, same body, same audit
	// result.
	if !ok || user.OrgDisabled {
		a.limits.lockout.fail(email, now)
		a.appendAudit(r.Context(), a.loginEvent(r, user, unknown, audit.ActionLoginFailure, audit.ResultFailed))
		httpx.WriteError(w, r, httpx.Unauthenticated("invalid email or password"))
		return
	}

	// Success: the failure history is cleared and a PAT is minted.
	a.limits.lockout.reset(email)

	token := idgen.Secret(idgen.PrefixPAT)
	if err := authstore.CreatePAT(r.Context(), conn, idgen.New("pat_"), user.ID, authstore.HashToken(token)); err != nil {
		a.logger().Error("login: store token", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	a.appendAudit(r.Context(), a.loginEvent(r, user, false, audit.ActionLoginSuccess, audit.ResultSuccess))

	view := userView{
		ID:                 user.ID,
		Email:              user.Email,
		Role:               user.Role,
		MustChangePassword: user.MustChangePassword,
	}
	if user.OrgID != "" {
		if org, err := authstore.OrgByID(r.Context(), conn, user.OrgID); err == nil {
			view.Organization = orgViewOf(org)
		} else if !errors.Is(err, authstore.ErrNotFound) {
			a.logger().Error("login: load organization", "error", err)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, loginResponse{Token: token, User: view})
}

// loginEvent builds a login audit event. A failure for an unknown email has no
// user and no organization, so it goes to the platform chain as an anonymous
// event: that is the only chain that can hold it.

// loginEvent builds a login audit event. A failure for an unknown email has no
// user and no organization, so it goes to the platform chain as an anonymous
// event: that is the only chain that can hold it.
func (a *api) loginEvent(r *http.Request, user authstore.User, unknown bool, action string, result audit.Result) audit.Event {
	sourceIP := a.sourceIP(r)
	if unknown || user.ID == "" {
		return audit.Event{
			Scope:     audit.PlatformScope,
			Timestamp: time.Now().UTC(),
			ActorKind: audit.ActorAnonymous,
			Action:    action,
			Target:    "auth/token",
			SourceIP:  sourceIP,
			Result:    result,
		}
	}

	actor := reqctx.Actor{
		Kind:    reqctx.KindUser,
		UserID:  user.ID,
		Email:   user.Email,
		OrgID:   user.OrgID,
		Role:    user.Role,
		TokenID: "",
	}
	if user.Role == reqctx.RolePlatformAdmin || user.OrgID == "" {
		actor.Kind = reqctx.KindPlatform
		actor.Role = reqctx.RolePlatformAdmin
	}
	return audit.Event{
		Scope:     scopeFor(actor),
		Timestamp: time.Now().UTC(),
		ActorID:   user.ID,
		ActorKind: actorKind(actor),
		OrgID:     orgOf(actor),
		Action:    action,
		Target:    "auth/token",
		SourceIP:  sourceIP,
		Result:    result,
	}
}

// writeRetryAfter advertises how long the caller should wait. It is set before the
// error body so the header survives WriteHeader.

// writeRetryAfter advertises how long the caller should wait. It is set before the
// error body so the header survives WriteHeader.
func writeRetryAfter(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}

// handleLogout implements POST /api/v1/auth/logout: the PAT that made the request
// is revoked on the server, so the credential is dead on the next request
// (SPEC §4).

// handleLogout implements POST /api/v1/auth/logout: the PAT that made the request
// is revoked on the server, so the credential is dead on the next request
// (SPEC §4).
func (a *api) handleLogout(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireActor(w, r)
	if !ok {
		return
	}
	if !actor.IsUser() && !actor.IsPlatform() {
		// A service token has no session to end. It can see that the route exists
		// but may not use it.
		a.deny(w, r, "auth/logout")
		return
	}

	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	revoked, err := authstore.RevokePAT(r.Context(), conn, actor.TokenID)
	if err != nil {
		a.logger().Error("logout: revoke token", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if revoked {
		a.appendAudit(r.Context(), a.auditEvent(r.Context(), actor, audit.ActionLogout, "auth/logout", audit.ResultSuccess))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

// handlePasswordChange implements POST /api/v1/auth/password (P1).
//
// On success it revokes every other PAT of the user, so a password change kills the
// sessions that were opened with the old password while leaving the caller's own
// token working (P1(b)), and it clears must_change_password (P1(a)).

// handlePasswordChange implements POST /api/v1/auth/password (P1).
//
// On success it revokes every other PAT of the user, so a password change kills the
// sessions that were opened with the old password while leaving the caller's own
// token working (P1(b)), and it clears must_change_password (P1(a)).
func (a *api) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireActor(w, r)
	if !ok {
		return
	}
	if !actor.IsUser() && !actor.IsPlatform() {
		// Service tokens have no password.
		a.deny(w, r, "auth/password")
		return
	}

	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	user, err := authstore.UserByID(r.Context(), conn, actor.UserID)
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			// The account was removed after the token resolved.
			httpx.WriteError(w, r, httpx.Unauthenticated("authentication required"))
			return
		}
		a.logger().Error("password: load user", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	matches, err := VerifyPassword(user.PasswordHash, req.CurrentPassword)
	if err != nil {
		a.logger().Error("password: stored hash is not valid argon2id", "user_id", user.ID)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if !matches {
		// A wrong current password is a validation failure on the payload, not a
		// credential that failed to resolve: the PAT is fine. Nothing about the
		// account is revealed, and the CLI maps 400 to a validation error.
		httpx.WriteError(w, r, httpx.Validation("current password is incorrect"))
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		a.logger().Error("password: hash", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// One transaction: the new hash, the cleared flag and the revocation of the
	// other sessions either all happen or none of them do. A password change that
	// committed while the revocations failed would leave old sessions alive.
	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("password: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	if err := authstore.SetPassword(r.Context(), tx, user.ID, hash, false); err != nil {
		a.logger().Error("password: store hash", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	revoked, err := authstore.RevokeOtherPATs(r.Context(), tx, user.ID, actor.TokenID)
	if err != nil {
		a.logger().Error("password: revoke other tokens", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("password: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"password_changed": true,
		"revoked_tokens":   revoked,
	})
}

// handleMe implements GET /api/v1/me.
//
// The three kinds of caller see three different documents, and that is the point:
// a platform admin has no organization, and a service token has a scope instead of
// an identity, so it never learns the organization or the user behind it.

// handleMe implements GET /api/v1/me.
//
// The three kinds of caller see three different documents, and that is the point:
// a platform admin has no organization, and a service token has a scope instead of
// an identity, so it never learns the organization or the user behind it.
func (a *api) handleMe(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireActor(w, r)
	if !ok {
		return
	}
	// /me is NOT on the must-change allowlist: a caller who has to change their
	// password may only reach /auth/password and /auth/logout, so this answers 403
	// with the machine-readable code until the flag clears.
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	switch {
	case actor.IsService():
		// A service token may only perform secret operations inside its scope
		// (SPEC §2.7), and /me is not one. The route is visible to the caller — the
		// token authenticated — so this is a 403 and not a 404. Ruled by the CEO and
		// ratified by the CTO: a service token gets no identity document at all, not
		// even one reduced to its scope.
		a.deny(w, r, "me")
		return

	case actor.IsPlatform():
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"role":         reqctx.RolePlatformAdmin,
			"organization": nil,
			"user": map[string]any{
				"id":    actor.UserID,
				"email": actor.Email,
			},
		})

	default:
		user, err := authstore.UserByIDInOrg(r.Context(), conn, actor.OrgID, actor.UserID)
		if err != nil {
			if errors.Is(err, authstore.ErrNotFound) {
				a.hide(w, r, "me")
				return
			}
			a.logger().Error("me: load user", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
		org, err := authstore.OrgByID(r.Context(), conn, user.OrgID)
		if err != nil {
			a.logger().Error("me: load organization", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"role":         user.Role,
			"organization": orgViewOf(org),
			"user": map[string]any{
				"id":                   user.ID,
				"email":                user.Email,
				"must_change_password": user.MustChangePassword,
			},
		})
	}
}

// sourceIP returns the resolved client address, falling back to resolving it from
// the request when middleware did not record one. One resolver, one answer.

// sourceIP returns the resolved client address, falling back to resolving it from
// the request when middleware did not record one. One resolver, one answer.
func (a *api) sourceIP(r *http.Request) string {
	if ip := reqctx.SourceIPFrom(r.Context()); ip != "" {
		return ip
	}
	return SourceIP(r, a.trustProxy())
}
