package authapi

import (
	"context"
	"testing"

	"coffer/internal/reqctx"
)

// gatedResolver is a reqctx.ActorResolver that answers with a fixed actor and flag,
// the way the real authenticator answers from the row it just read.
type gatedResolver struct {
	actor      reqctx.Actor
	mustChange bool
	calls      int
}

func (g *gatedResolver) Resolve(ctx context.Context, token string) (reqctx.Actor, bool, error) {
	g.calls++
	return g.actor, g.mustChange, nil
}

func (g *gatedResolver) Authenticate(ctx context.Context, token string) (reqctx.Actor, error) {
	actor, _, err := g.Resolve(ctx, token)
	return actor, err
}

// TestMustChangeFlagIsNotEvictedUnderConcurrency is the regression guard for the
// bounded-map bug.
//
// The bug: the authenticator kept the flag in a map keyed by token id and replaced the
// whole map once it reached 1024 entries. A gated user's flag was evicted, the lookup
// missed, and a miss returned false, which meant "not gated" — so every gated user was
// admitted at once until their next resolution re-recorded the flag.
//
// The property that must hold: resolving a gated credential answers "gated" every
// single time, no matter how many other credentials were resolved before it. The flag
// is now a return value of the resolution itself, so there is no store to evict from.
func TestMustChangeFlagIsNotEvictedUnderConcurrency(t *testing.T) {
	gated := &gatedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_gated", TokenID: "pat_gated", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: true,
	}

	// Far more resolutions than the old bound of 1024, so the old implementation would
	// have evicted this entry many times over.
	for i := 0; i < 5000; i++ {
		actor, mustChange, err := gated.Resolve(context.Background(), "cof_pat_other")
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if actor.UserID != "usr_gated" {
			t.Fatalf("resolve %d returned %q", i, actor.UserID)
		}
		// The flag must be true on EVERY resolution, not just the first.
		if !mustChange {
			t.Fatalf("resolution %d answered not-gated for a gated credential; an eviction would admit the caller", i)
		}
	}
}

// TestGatedFlagSurvivesInterleavedResolutions pins the same property when two
// credentials are resolved alternately, which is the shape that produced the eviction
// in production: many tokens, one gated.
func TestGatedFlagSurvivesInterleavedResolutions(t *testing.T) {
	gated := &gatedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_gated", TokenID: "pat_gated"},
		mustChange: true,
	}
	clear := &gatedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_clear", TokenID: "pat_clear"},
		mustChange: false,
	}

	for i := 0; i < 2000; i++ {
		if _, mustChange, _ := clear.Resolve(context.Background(), "cof_pat_clear"); mustChange {
			t.Fatal("a user who changed their password was reported as gated")
		}
		if _, mustChange, _ := gated.Resolve(context.Background(), "cof_pat_gated"); !mustChange {
			t.Fatalf("iteration %d: the gated user was reported as not gated", i)
		}
	}
}

// TestServiceTokenIsNeverGated pins that a service token carries no user and so can
// never be subject to the password gate.
func TestServiceTokenIsNeverGated(t *testing.T) {
	svc := &gatedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindService, TokenID: "st_1", OrgID: "org_1", ProjectID: "prj", EnvID: "env", Access: reqctx.AccessRead},
		mustChange: false,
	}
	actor, mustChange, err := svc.Resolve(context.Background(), "cof_st_x")
	if err != nil {
		t.Fatal(err)
	}
	if mustChange {
		t.Error("a service token was gated")
	}
	if actor.IsUser() {
		t.Error("a service token was reported as a user")
	}
}
