package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

// Principal kinds.
const (
	KindPlatform = "platform_admin"
	KindUser     = "user"
	KindService  = "service_token"
)

// Principal is an authenticated caller, re-loaded from the DB on every request.
type Principal struct {
	Kind    string
	TokenID string

	// Users (platform admin and org users).
	UserID             string
	Email              string
	Role               string // platform_admin|owner|admin|member
	MustChangePassword bool

	// Org users and service tokens.
	OrgID   string
	OrgSlug string

	// Service tokens.
	ProjectID   string
	ProjectSlug string
	EnvID       string
	EnvSlug     string
	Access      string // read|read-write
	CreatedBy   string
	ExpiresAt   time.Time
}

// ActorType is the audit actor type.
func (p *Principal) ActorType() string {
	if p == nil {
		return "anonymous"
	}
	if p.Kind == KindService {
		return "service_token"
	}
	return "user"
}

// ActorID is the audit actor id (user id or token id).
func (p *Principal) ActorID() string {
	if p == nil {
		return ""
	}
	if p.Kind == KindService {
		return p.TokenID
	}
	return p.UserID
}

// Chain is the audit chain the principal's events go to.
func (p *Principal) Chain() string {
	if p == nil || p.Kind == KindPlatform {
		return audit.PlatformChain
	}
	return p.OrgID
}

// isOA reports whether p is an org owner or admin.
func (p *Principal) isOA() bool {
	return p.Kind == KindUser && (p.Role == "owner" || p.Role == "admin")
}

// humanID is the user responsible for an action: the user, or a service
// token's creator.
func (p *Principal) humanID() string {
	if p.Kind == KindService {
		return p.CreatedBy
	}
	return p.UserID
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	if !crypto.WellFormedToken(tok) {
		return "", false
	}
	return tok, true
}

// lookupToken resolves a bearer token to a principal, checking the token,
// its user and its org in one query. It returns nil for anything invalid.
func (s *Server) lookupToken(ctx context.Context, tok string) (*Principal, error) {
	hash := crypto.TokenHash(tok)
	var (
		storedHash                                  []byte
		tokenID, kind                               string
		tokOrg, userID, createdBy, projectID, envID *string
		access                                      *string
		expiresAt                                   time.Time
		lastUsed                                    *time.Time
		uID, uEmail, uRole, uOrg                    *string
		uMust                                       *bool
		oID, oSlug                                  *string
		oDisabled                                   *bool
		pSlug, pOrg, eSlug, eProject                *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.token_hash, t.kind, t.org_id, t.user_id, t.created_by, t.project_id, t.env_id, t.access,
		       t.expires_at, t.last_used_at,
		       u.id, u.email, u.role, u.org_id, u.must_change_password,
		       o.id, o.slug, o.disabled,
		       p.slug, p.org_id, e.slug, e.project_id
		FROM tokens t
		LEFT JOIN users u ON u.id = t.user_id
		LEFT JOIN orgs o ON o.id = t.org_id
		LEFT JOIN projects p ON p.id = t.project_id
		LEFT JOIN environments e ON e.id = t.env_id
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now()`, hash).Scan(
		&tokenID, &storedHash, &kind, &tokOrg, &userID, &createdBy, &projectID, &envID, &access,
		&expiresAt, &lastUsed,
		&uID, &uEmail, &uRole, &uOrg, &uMust,
		&oID, &oSlug, &oDisabled,
		&pSlug, &pOrg, &eSlug, &eProject)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(storedHash, hash) != 1 {
		return nil, nil
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	p := &Principal{TokenID: tokenID, ExpiresAt: expiresAt}
	switch kind {
	case "pat":
		if uID == nil || userID == nil || *uID != *userID {
			return nil, nil // user removed
		}
		p.UserID, p.Email, p.Role = *uID, str(uEmail), str(uRole)
		p.MustChangePassword = uMust != nil && *uMust
		if p.Role == "platform_admin" {
			if uOrg != nil || tokOrg != nil {
				return nil, nil
			}
			p.Kind = KindPlatform
		} else {
			// The token's org must be the user's org and must be enabled.
			if uOrg == nil || tokOrg == nil || *uOrg != *tokOrg || oID == nil || oDisabled == nil || *oDisabled {
				return nil, nil
			}
			p.Kind = KindUser
			p.OrgID, p.OrgSlug = *oID, str(oSlug)
		}
	case "service":
		if oID == nil || oDisabled == nil || *oDisabled || projectID == nil || envID == nil || access == nil ||
			pOrg == nil || *pOrg != *oID || eProject == nil || *eProject != *projectID {
			return nil, nil
		}
		p.Kind = KindService
		p.OrgID, p.OrgSlug = *oID, str(oSlug)
		p.ProjectID, p.ProjectSlug = *projectID, str(pSlug)
		p.EnvID, p.EnvSlug = *envID, str(eSlug)
		p.Access = *access
		p.CreatedBy = str(createdBy)
	default:
		return nil, nil
	}
	s.touch(p.TokenID, lastUsed)
	return p, nil
}

// touch updates last_used_at at most once per minute per token, in the
// background (best effort).
func (s *Server) touch(tokenID string, last *time.Time) {
	now := time.Now()
	if last != nil && now.Sub(*last) < time.Minute {
		return
	}
	if v, ok := s.lastUsed.Load(tokenID); ok && now.Sub(v.(time.Time)) < time.Minute {
		return
	}
	s.lastUsed.Store(tokenID, now)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.pool.Exec(ctx, `UPDATE tokens SET last_used_at=now() WHERE id=$1`, tokenID)
	}()
}

// authenticate returns the principal for r or a 401.
func (s *Server) authenticate(r *http.Request) (*Principal, *apiError) {
	tok, ok := bearer(r)
	if !ok {
		return nil, errUnauth
	}
	p, err := s.lookupToken(r.Context(), tok)
	if err != nil {
		s.log.Error("token lookup failed", "request_id", info(r).id, "error", err.Error())
		return nil, errInternal
	}
	if p == nil {
		return nil, errUnauth
	}
	return p, nil
}

// ---------------------------------------------------------------- audit helpers

func (s *Server) event(r *http.Request, p *Principal, action, target, result string, details map[string]any) *audit.Event {
	e := &audit.Event{
		Chain: p.Chain(), ActorType: p.ActorType(), ActorID: p.ActorID(), Action: action,
		Target: target, SourceIP: s.clientIP(r), Result: result, Details: details,
	}
	if p != nil && p.Kind != KindPlatform {
		e.OrgID = p.OrgID
	}
	return e
}

// audit appends a standalone event via the group committer and waits for
// the commit. Failures are logged; callers that must not proceed without the
// event use auditStrict.
func (s *Server) audit(r *http.Request, p *Principal, action, target, result string, details map[string]any) {
	if err := s.appender.Append(r.Context(), s.event(r, p, action, target, result, details)); err != nil {
		s.log.Error("audit append failed", "request_id", info(r).id, "action", action, "error", err.Error())
	}
}

// deny audits an authorization denial and writes the 403/404 response.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, p *Principal, e *apiError) {
	s.audit(r, p, "authz.denied", deniedTarget(r), audit.Denied, map[string]any{"status": e.status})
	writeError(w, e)
}

// ---------------------------------------------------------------- /auth

type loginReq struct {
	Email    *string `json:"email"`
	Password *string `json:"password"`
}

type userJSON struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	Role               string  `json:"role"`
	OrgID              *string `json:"org_id"`
	OrgSlug            *string `json:"org_slug"`
	MustChangePassword bool    `json:"must_change_password"`
}

func emailTarget(norm string) string {
	h := sha256.Sum256([]byte(norm))
	return "email:" + hex.EncodeToString(h[:])[:16]
}

func lockKey(norm string) int64 {
	h := sha256.Sum256([]byte("coffer/login|" + norm))
	return int64(binary.BigEndian.Uint64(h[:8]))
}

const (
	lockoutMax    = 5
	lockoutWindow = 15 * time.Minute
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ *Principal) {
	// A service token can never create a PAT. Any other Authorization header
	// (PAT, garbage) is ignored and this is treated as a normal login.
	if tok, ok := bearer(r); ok && strings.HasPrefix(tok, crypto.ServicePrefix) {
		p, err := s.lookupToken(r.Context(), tok)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if p != nil {
			info(r).actor = p.ActorID()
			s.deny(w, r, p, errForbidden)
			return
		}
	}
	var req loginReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Email == nil || req.Password == nil {
		writeError(w, badRequest("email and password are required"))
		return
	}
	norm, valid := config.NormalizeEmail(*req.Email)
	if !valid {
		// Never stored or queried as-is (could be huge or contain NUL); a
		// stable digest still gives malformed inputs a lockout bucket.
		norm = "invalid:" + emailTarget(norm)
	}
	password := *req.Password

	// Queue for a hashing slot on the request context (a client that leaves
	// while queued has made no attempt). Once the attempt starts, all its DB
	// work runs on a context the client cannot cancel, so a disconnect
	// mid-verify can neither skip the lockout counter nor the audit event.
	release, err := s.hasher.Slot(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer release()
	ctx, cancel := detached(r)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(norm)); err != nil {
		s.internalError(w, r, err)
		return
	}

	var (
		uID, uEmail, uHash, uRole string
		uOrg, oSlug               *string
		uMust                     bool
		oDisabled                 *bool
		found                     bool
	)
	if valid {
		err = tx.QueryRow(ctx, `SELECT u.id, u.email, u.password_hash, u.role, u.org_id, u.must_change_password, o.slug, o.disabled
			FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.email_norm=$1`, norm).Scan(
			&uID, &uEmail, &uHash, &uRole, &uOrg, &uMust, &oSlug, &oDisabled)
		switch {
		case err == nil:
			found = true
		case errors.Is(err, pgx.ErrNoRows):
		default:
			s.internalError(w, r, err)
			return
		}
	}

	// Audit routing (SPEC §4 "Where events go"): a successful login is the
	// user's own event and goes to their chain (org, or platform for the
	// platform admin). A failed or locked attempt is by an unauthenticated
	// caller, so it always goes to the platform chain; when the email belongs
	// to an org user a copy also goes to that org's chain so its admins see
	// attacks on their users. Platform first, then org: a fixed lock order.
	//
	// The platform-chain copy of a failure is identical in shape for known
	// and unknown emails (target email:<hash>, no user or org id): the
	// platform admin can never learn an org's members from it (SPEC §1).
	// Only the org-chain copy names the user.
	appendLogin := func(result string, details map[string]any) error {
		if result == audit.Success {
			e := &audit.Event{Chain: audit.PlatformChain, ActorType: "user", ActorID: uID, Action: "auth.login",
				Target: uID, SourceIP: s.clientIP(r), Result: result, Details: details}
			if uOrg != nil {
				e.Chain, e.OrgID = *uOrg, *uOrg
			}
			return audit.AppendTx(ctx, tx, e)
		}
		plat := &audit.Event{Chain: audit.PlatformChain, ActorType: "anonymous", ActorID: "", Action: "auth.login",
			Target: emailTarget(norm), SourceIP: s.clientIP(r), Result: result, Details: details}
		if err := audit.AppendTx(ctx, tx, plat); err != nil {
			return err
		}
		if found && uOrg != nil {
			c := *plat
			c.Chain, c.OrgID, c.Target = *uOrg, *uOrg, uID
			return audit.AppendTx(ctx, tx, &c)
		}
		return nil
	}

	// Expired failures never count again; prune this email's rows on every
	// attempt and, occasionally, everyone's (unknown-email spam).
	if _, err := tx.Exec(ctx, `DELETE FROM login_failures WHERE email_norm=$1 AND failed_at <= now() - $2::interval`,
		norm, lockoutWindow.String()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.maybePruneLoginFailures()

	var failures int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM login_failures WHERE email_norm=$1 AND failed_at > now() - $2::interval`,
		norm, lockoutWindow.String()).Scan(&failures); err != nil {
		s.internalError(w, r, err)
		return
	}
	if failures >= lockoutMax {
		if err := appendLogin(audit.Denied, map[string]any{"reason": "locked"}); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errRateLimited)
		return
	}

	ok := false
	if found {
		ok = s.hasher.VerifyHeld(uHash, password)
		if uOrg != nil && (oDisabled == nil || *oDisabled) {
			ok = false
		}
	} else {
		s.hasher.DummyHeld(password)
	}
	if !ok {
		if _, err := tx.Exec(ctx, `INSERT INTO login_failures (email_norm, failed_at) VALUES ($1, now())`, norm); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := appendLogin(audit.Failed, nil); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errBadCreds)
		return
	}

	if _, err := tx.Exec(ctx, `DELETE FROM login_failures WHERE email_norm=$1`, norm); err != nil {
		s.internalError(w, r, err)
		return
	}
	// Upgrade hashes made with other parameters (e.g. after
	// COFFER_ARGON2_MEMORY_KIB changed) so known accounts verify at the same
	// cost as the unknown-email dummy hash.
	if s.hasher.NeedsRehash(uHash) {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, s.hasher.HashHeld(password), uID); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	tok := crypto.NewToken(crypto.PATPrefix)
	tokID := crypto.NewID("tok")
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `INSERT INTO tokens (id, kind, token_hash, org_id, user_id, name, expires_at)
		VALUES ($1, 'pat', $2, $3, $4, 'login', now() + $5::interval) RETURNING expires_at`,
		tokID, crypto.TokenHash(tok), uOrg, uID, s.cfg.PATTTL.String()).Scan(&expiresAt); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := appendLogin(audit.Success, map[string]any{"token_id": tokID}); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	info(r).actor = uID
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      tok,
		"expires_at": ts(expiresAt),
		"user": userJSON{ID: uID, Email: uEmail, Role: uRole, OrgID: uOrg, OrgSlug: oSlug,
			MustChangePassword: uMust && s.cfg.RequirePasswordChange},
	})
}

// detached returns a context for work that must complete once started even
// if the client goes away (security-relevant counters and audit events).
func detached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
}

// maybePruneLoginFailures removes expired login_failures rows for every
// email, at most once a minute, in the background.
func (s *Server) maybePruneLoginFailures() {
	now := time.Now().UnixNano()
	last := s.lastPrune.Load()
	if now-last < int64(time.Minute) || !s.lastPrune.CompareAndSwap(last, now) {
		return
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(ctx, `DELETE FROM login_failures WHERE failed_at <= now() - $1::interval`, lockoutWindow.String()); err != nil {
			s.log.Warn("login_failures prune failed", "error", err.Error())
		}
	}()
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindService {
		s.deny(w, r, p, errForbidden)
		return
	}
	// Revocation must not be undone by the client hanging up.
	ctx, cancel := detached(r)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `UPDATE tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, p.TokenID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "auth.logout", p.TokenID, audit.Success, nil)); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

type passwordReq struct {
	CurrentPassword *string `json:"current_password"`
	NewPassword     *string `json:"new_password"`
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindService {
		s.deny(w, r, p, errForbidden)
		return
	}
	var req passwordReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.CurrentPassword == nil || req.NewPassword == nil {
		writeError(w, badRequest("current_password and new_password are required"))
		return
	}
	if err := config.CheckPassword(*req.NewPassword); err != nil {
		writeError(w, badRequest(err.Error()))
		return
	}
	if *req.NewPassword == *req.CurrentPassword {
		writeError(w, badRequest("new password must differ from the current password"))
		return
	}
	release, err := s.hasher.Slot(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer release()
	// As for login: the attempt's counter and audit event must survive a
	// client disconnect.
	ctx, cancel := detached(r)
	defer cancel()
	norm, _ := config.NormalizeEmail(p.Email)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(norm)); err != nil {
		s.internalError(w, r, err)
		return
	}
	var failures int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM login_failures WHERE email_norm=$1 AND failed_at > now() - $2::interval`,
		norm, lockoutWindow.String()).Scan(&failures); err != nil {
		s.internalError(w, r, err)
		return
	}
	if failures >= lockoutMax {
		if err := audit.AppendTx(ctx, tx, s.event(r, p, "auth.password_change", p.UserID, audit.Denied, map[string]any{"reason": "locked"})); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errRateLimited)
		return
	}
	var hash string
	if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1 FOR UPDATE`, p.UserID).Scan(&hash); err != nil {
		s.internalError(w, r, err)
		return
	}
	if !s.hasher.VerifyHeld(hash, *req.CurrentPassword) {
		if _, err := tx.Exec(ctx, `INSERT INTO login_failures (email_norm, failed_at) VALUES ($1, now())`, norm); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := audit.AppendTx(ctx, tx, s.event(r, p, "auth.password_change", p.UserID, audit.Failed, nil)); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errForbidden)
		return
	}
	newHash := s.hasher.HashHeld(*req.NewPassword)
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$1, must_change_password=false, password_changed_at=now() WHERE id=$2`, newHash, p.UserID); err != nil {
		s.internalError(w, r, err)
		return
	}
	tag, err := tx.Exec(ctx, `UPDATE tokens SET revoked_at=now() WHERE user_id=$1 AND kind='pat' AND id<>$2 AND revoked_at IS NULL`, p.UserID, p.TokenID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM login_failures WHERE email_norm=$1`, norm); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "auth.password_change", p.UserID, audit.Success,
		map[string]any{"revoked_tokens": tag.RowsAffected()})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindService {
		writeJSON(w, http.StatusOK, map[string]any{
			"type": "service_token", "id": p.TokenID, "org_id": p.OrgID, "org_slug": p.OrgSlug,
			"project": p.ProjectSlug, "env": p.EnvSlug, "access": p.Access, "expires_at": ts(p.ExpiresAt),
		})
		return
	}
	var org, slug *string
	if p.Kind == KindUser {
		org, slug = &p.OrgID, &p.OrgSlug
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type": "user", "id": p.UserID, "email": p.Email, "role": p.Role, "org_id": org, "org_slug": slug,
		"must_change_password": p.MustChangePassword && s.cfg.RequirePasswordChange,
	})
}
