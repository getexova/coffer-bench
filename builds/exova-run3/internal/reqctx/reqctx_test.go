package reqctx

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestFromDefaultsToAnonymous(t *testing.T) {
	// The fail-closed default: a handler that never had an actor resolved sees an
	// anonymous actor, not a privileged zero value.
	actor := From(context.Background())
	if !actor.IsAnonymous() {
		t.Errorf("From(empty ctx) = %+v, want anonymous", actor)
	}
	if actor.Kind != KindAnonymous {
		t.Errorf("Kind = %q, want %q", actor.Kind, KindAnonymous)
	}

	// A nil context must not panic.
	if got := From(nil); !got.IsAnonymous() {
		t.Errorf("From(nil) = %+v, want anonymous", got)
	}
}

func TestWithActorRoundTrip(t *testing.T) {
	want := Actor{
		Kind:      KindService,
		TokenID:   "st_1",
		OrgID:     "org_1",
		ProjectID: "prj_1",
		EnvID:     "env_1",
		Access:    AccessReadWrite,
	}

	ctx := WithActor(context.Background(), want)
	got := From(ctx)

	if got != want {
		t.Errorf("From(WithActor(a)) = %+v, want %+v", got, want)
	}
	if !got.IsService() {
		t.Error("IsService() = false for a service actor")
	}
	if got.IsUser() || got.IsPlatform() || got.IsAnonymous() {
		t.Error("a service actor reported as another kind")
	}
}

func TestAnEmptyKindIsAnonymous(t *testing.T) {
	// A stored actor with an empty Kind must not become a privileged actor.
	ctx := WithActor(context.Background(), Actor{UserID: "usr_1", Role: RoleOwner})
	if got := From(ctx); !got.IsAnonymous() {
		t.Errorf("From = %+v, want anonymous for an actor with no kind", got)
	}
}

func TestActorPredicates(t *testing.T) {
	tests := []struct {
		name                               string
		actor                              Actor
		anonymous, service, platform, user bool
	}{
		{"anonymous", Actor{Kind: KindAnonymous}, true, false, false, false},
		{"user", Actor{Kind: KindUser, Role: RoleMember}, false, false, false, true},
		{"service", Actor{Kind: KindService}, false, true, false, false},
		{"platform", Actor{Kind: KindPlatform, Role: RolePlatformAdmin}, false, false, true, false},
		{"platform by role", Actor{Kind: KindUser, Role: RolePlatformAdmin}, false, false, true, true},
		{"zero", Actor{}, true, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.actor.IsAnonymous(); got != tt.anonymous {
				t.Errorf("IsAnonymous() = %v, want %v", got, tt.anonymous)
			}
			if got := tt.actor.IsService(); got != tt.service {
				t.Errorf("IsService() = %v, want %v", got, tt.service)
			}
			if got := tt.actor.IsPlatform(); got != tt.platform {
				t.Errorf("IsPlatform() = %v, want %v", got, tt.platform)
			}
			if got := tt.actor.IsUser(); got != tt.user {
				t.Errorf("IsUser() = %v, want %v", got, tt.user)
			}
		})
	}
}

func TestSetActorMutatesRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	SetActor(req, Actor{Kind: KindUser, UserID: "usr_1", OrgID: "org_1", Role: RoleOwner})

	got := From(req.Context())
	if got.UserID != "usr_1" || got.Kind != KindUser {
		t.Errorf("From after SetActor = %+v", got)
	}

	// A nil request must not panic.
	SetActor(nil, Actor{Kind: KindUser})
}

func TestRecorderKeepsFirstDenial(t *testing.T) {
	ctx := WithRecorder(context.Background(), &Recorder{})

	Deny(ctx, "org_1", "secret.write", "project/prj_1/env/env_1/key/A")
	Deny(ctx, "org_1", "secret.delete", "project/prj_1/env/env_1/key/B")

	rec := RecorderFrom(ctx)
	first, ok := rec.First()
	if !ok {
		t.Fatal("First() reported no denial")
	}
	if first.Action != "secret.write" {
		t.Errorf("first denial action = %q, want the first recorded", first.Action)
	}
	if len(rec.Denials()) != 1 {
		t.Errorf("Denials() has %d entries, want exactly 1", len(rec.Denials()))
	}
}

func TestDenyWithoutRecorderIsNoOp(t *testing.T) {
	// A handler must never panic because middleware did not install a recorder.
	Deny(context.Background(), "org_1", "secret.write", "target")
	Deny(nil, "org_1", "secret.write", "target")
}

func TestRecorderNilSafety(t *testing.T) {
	var rec *Recorder
	rec.Add(Denial{Scope: "s", Action: "a", Target: "t"})
	if got := rec.Denials(); got != nil {
		t.Errorf("Denials() on a nil recorder = %v, want nil", got)
	}
	if _, ok := rec.First(); ok {
		t.Error("First() on a nil recorder reported a denial")
	}

	if got := RecorderFrom(nil); got != nil {
		t.Errorf("RecorderFrom(nil) = %v, want nil", got)
	}
	if got := RecorderFrom(context.Background()); got != nil {
		t.Errorf("RecorderFrom(empty) = %v, want nil", got)
	}
}

func TestDenialsReturnsACopy(t *testing.T) {
	ctx := WithRecorder(context.Background(), &Recorder{})
	Deny(ctx, "org_1", "secret.read", "target")

	denials := RecorderFrom(ctx).Denials()
	denials[0].Action = "mutated"

	first, _ := RecorderFrom(ctx).First()
	if first.Action != "secret.read" {
		t.Error("Denials() exposed the internal slice")
	}
}

func TestSourceIP(t *testing.T) {
	ctx := WithSourceIP(context.Background(), "203.0.113.9")
	if got := SourceIPFrom(ctx); got != "203.0.113.9" {
		t.Errorf("SourceIPFrom = %q", got)
	}
	if got := SourceIPFrom(context.Background()); got != "" {
		t.Errorf("SourceIPFrom(empty) = %q, want empty", got)
	}
	if got := SourceIPFrom(nil); got != "" {
		t.Errorf("SourceIPFrom(nil) = %q, want empty", got)
	}
}

func TestMustChangePassword(t *testing.T) {
	ctx := WithMustChangePassword(context.Background(), true)
	if !MustChangePasswordFrom(ctx) {
		t.Error("MustChangePasswordFrom = false, want true")
	}
	if MustChangePasswordFrom(context.Background()) {
		t.Error("MustChangePasswordFrom defaults to true")
	}
	if MustChangePasswordFrom(nil) {
		t.Error("MustChangePasswordFrom(nil) = true")
	}
}

func TestErrUnauthenticatedIsComparable(t *testing.T) {
	// Middleware uses errors.Is on this sentinel to decide 401 versus 500.
	wrapped := errors.Join(errors.New("token not found"), ErrUnauthenticated)
	if !errors.Is(wrapped, ErrUnauthenticated) {
		t.Error("errors.Is could not find ErrUnauthenticated through a wrap")
	}
}

func TestRoleAndAccessConstants(t *testing.T) {
	if RoleOwner != "owner" || RoleAdmin != "admin" || RoleMember != "member" || RolePlatformAdmin != "platform_admin" {
		t.Error("role constants do not match the schema")
	}
	if AccessRead != "read" || AccessReadWrite != "read-write" {
		t.Error("access constants do not match the schema")
	}
	if KindUser != "user" || KindService != "service" || KindPlatform != "platform" || KindAnonymous != "anonymous" {
		t.Error("kind constants do not match the audit actor kinds")
	}
}
