// Package reqctx carries the resolved actor and the denial record for one
// request (docs/CONTRACTS.md §8).
//
// The actor is resolved once, by middleware, and read by every handler and store
// call below it. From returns an anonymous Actor when nothing has been set, so a
// handler that forgets to check authentication fails closed instead of running as
// nobody-in-particular with access.
//
// The Recorder is how a denial reaches the audit log. A handler that decides a
// request is invisible calls Deny and writes its 404; the middleware's central
// flush turns the recorded denial into a `denied` audit event for the 403/404
// response. Denials are never written for 401, because an unauthenticated request
// has no actor to attribute and would let an anonymous caller write freely.
package reqctx

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// Kind is the kind of principal behind a request.
type Kind string

const (
	KindAnonymous Kind = "anonymous"
	KindUser      Kind = "user"
	KindService   Kind = "service"
	KindPlatform  Kind = "platform"
)

// Access is a service token's access level.
type Access string

const (
	AccessNone      Access = ""
	AccessRead      Access = "read"
	AccessReadWrite Access = "read-write"
)

// Org roles, as stored in users.role.
const (
	RoleOwner         = "owner"
	RoleAdmin         = "admin"
	RoleMember        = "member"
	RolePlatformAdmin = "platform_admin"
)

// Actor is the authenticated principal for one request. The zero value is
// anonymous, which is the fail-closed default.
type Actor struct {
	Kind Kind
	// UserID is the user behind a PAT. Empty for service tokens.
	UserID string
	// TokenID is the personal_access_tokens.id or service_tokens.id.
	TokenID string
	Email   string
	// OrgID is empty for the platform admin, who belongs to no organization.
	OrgID string
	// Role is owner|admin|member|platform_admin.
	Role string
	// ProjectID and EnvID are the scope of a service token and are empty for
	// every other kind.
	ProjectID string
	EnvID     string
	// Access is a service token's read|read-write.
	Access Access
}

// IsAnonymous reports whether no credential was presented or it did not resolve.
func (a Actor) IsAnonymous() bool { return a.Kind == "" || a.Kind == KindAnonymous }

// IsService reports whether the caller is a service token.
func (a Actor) IsService() bool { return a.Kind == KindService }

// IsPlatform reports whether the caller is the platform admin.
func (a Actor) IsPlatform() bool { return a.Kind == KindPlatform || a.Role == RolePlatformAdmin }

// IsUser reports whether the caller is a person holding a PAT.
func (a Actor) IsUser() bool { return a.Kind == KindUser }

type actorKey struct{}

// WithActor returns a context carrying a. An anonymous actor is stored as absent
// so From's fail-closed default is the single code path.
func WithActor(ctx context.Context, a Actor) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, actorKey{}, a)
}

// From returns the actor for ctx, or an anonymous Actor when none was set.
func From(ctx context.Context) Actor {
	if ctx == nil {
		return Actor{Kind: KindAnonymous}
	}
	if a, ok := ctx.Value(actorKey{}).(Actor); ok && a.Kind != "" {
		return a
	}
	return Actor{Kind: KindAnonymous}
}

// SetActor attaches a to the request in place. Middleware uses it so handlers that
// only hold the *http.Request see the actor.
func SetActor(r *http.Request, a Actor) {
	if r == nil {
		return
	}
	*r = *r.WithContext(WithActor(r.Context(), a))
}

// sourceIPKey carries the resolved client address for the request. It is kept out
// of Actor so that Actor stays the frozen §8 shape, and it is resolved exactly
// once by middleware so the per-IP throttle and the audit event agree.
type sourceIPKey struct{}

// WithSourceIP records the resolved client address on ctx.
func WithSourceIP(ctx context.Context, ip string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sourceIPKey{}, ip)
}

// SourceIPFrom returns the resolved client address, or "" when unknown.
func SourceIPFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ip, _ := ctx.Value(sourceIPKey{}).(string)
	return ip
}

type mustChangePasswordKey struct{}

// WithMustChangePassword records the must-change-password flag on ctx.
func WithMustChangePassword(ctx context.Context, must bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, mustChangePasswordKey{}, must)
}

// MustChangePasswordFrom reports whether the caller must change their password
// before doing anything else (SPEC §4, P1).
func MustChangePasswordFrom(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	must, _ := ctx.Value(mustChangePasswordKey{}).(bool)
	return must
}

// ErrUnauthenticated is returned by an Authenticator for a missing, malformed,
// unknown, expired or revoked credential, and for a disabled organization.
var ErrUnauthenticated = errors.New("reqctx: unauthenticated")

// Authenticator resolves a bearer token to an Actor. It is implemented by the auth
// slice and called only by middleware; a handler never parses Authorization.
//
// Implementations must return ErrUnauthenticated (or an error wrapping it) for a
// credential that does not resolve, and must not return a partially populated
// Actor with a nil error.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Actor, error)
}

// ActorResolver is an optional capability an Authenticator may implement to return
// the must-change-password flag alongside the actor.
//
// The flag travels as a return value, per request, and is never stored anywhere. That
// is deliberate and load-bearing: an authorization decision must not be able to miss.
// A side cache keyed by token id has a miss path, and a miss path on this particular
// boolean is an allow. Returning the value with the actor means there is no cache, no
// eviction, and no state that can disagree with the credential that was just checked.
//
// It is a separate interface rather than a change to Authenticator so the frozen
// interface keeps working for any existing implementation. An implementation that does
// not provide it is still safe: middleware then treats the flag as set, and the caller
// is refused until the password is changed rather than being admitted.
type ActorResolver interface {
	Resolve(ctx context.Context, token string) (actor Actor, mustChangePassword bool, err error)
}

// Denial is one refused request, ready to become a `denied` audit event.
type Denial struct {
	// Scope is the chain the event belongs to: the actor's organization, or
	// audit.PlatformScope.
	Scope string
	// Action is the audit action the request was attempting, e.g. secret.write.
	Action string
	// Target names the resource the request addressed, e.g.
	// "project/<id>/env/<id>/key/API_KEY".
	Target string
}

type recorderKey struct{}

// Recorder collects the denials of one request. It is safe for concurrent use,
// and it keeps the first denial only: a request has one outcome, and the first
// refusal is the one that explains it.
type Recorder struct {
	mu      sync.Mutex
	denials []Denial
}

// WithRecorder attaches rec to ctx. Middleware installs one per request.
func WithRecorder(ctx context.Context, rec *Recorder) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if rec == nil {
		rec = &Recorder{}
	}
	return context.WithValue(ctx, recorderKey{}, rec)
}

// RecorderFrom returns the recorder for ctx, or nil when none was installed.
func RecorderFrom(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(recorderKey{}).(*Recorder)
	return rec
}

// Deny records that the request was refused for scope/action/target. It is a
// no-op when no recorder is installed, so a handler is never coupled to
// middleware having run, and it never panics.
func Deny(ctx context.Context, scope, action, target string) {
	rec := RecorderFrom(ctx)
	if rec == nil {
		return
	}
	rec.Add(Denial{Scope: scope, Action: action, Target: target})
}

// Add records a denial, keeping only the first.
func (r *Recorder) Add(d Denial) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.denials) > 0 {
		return
	}
	r.denials = append(r.denials, d)
}

// Denials returns a copy of the recorded denials, which is at most one.
func (r *Recorder) Denials() []Denial {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Denial, len(r.denials))
	copy(out, r.denials)
	return out
}

// First returns the first recorded denial.
func (r *Recorder) First() (Denial, bool) {
	if r == nil {
		return Denial{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.denials) == 0 {
		return Denial{}, false
	}
	return r.denials[0], true
}
