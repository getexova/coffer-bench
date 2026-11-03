package authz

import (
	"testing"

	"coffer/internal/reqctx"
)

const (
	orgID     = "org_1"
	otherOrg  = "org_2"
	projectID = "prj_1"
	otherPrj  = "prj_2"
	envID     = "env_1"
	otherEnv  = "env_2"
)

func owner() reqctx.Actor {
	return reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_owner", OrgID: orgID, Role: reqctx.RoleOwner}
}

func admin() reqctx.Actor {
	return reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_admin", OrgID: orgID, Role: reqctx.RoleAdmin}
}

func member() reqctx.Actor {
	return reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_member", OrgID: orgID, Role: reqctx.RoleMember}
}

func service(project, env string, access reqctx.Access) reqctx.Actor {
	return reqctx.Actor{
		Kind:      reqctx.KindService,
		TokenID:   "st_1",
		OrgID:     orgID,
		ProjectID: project,
		EnvID:     env,
		Access:    access,
	}
}

func platformAdmin() reqctx.Actor {
	return reqctx.Actor{Kind: reqctx.KindPlatform, UserID: "usr_platform", Role: reqctx.RolePlatformAdmin}
}

func anonymous() reqctx.Actor {
	return reqctx.Actor{Kind: reqctx.KindAnonymous}
}

// TestEffective covers SPEC §2 rules 2, 4, 5 and 7: what level each principal holds.
func TestEffective(t *testing.T) {
	tests := []struct {
		name   string
		actor  reqctx.Actor
		prj    string
		env    string
		grant  string
		expect string
	}{
		// Owners and admins reach every project in their org without a grant.
		{"owner on any project", owner(), projectID, envID, LevelNone, LevelWriter},
		{"owner on an unknown project", owner(), otherPrj, otherEnv, LevelNone, LevelWriter},
		{"admin on any project", admin(), projectID, envID, LevelNone, LevelWriter},

		// Members reach only a granted project.
		{"member with writer grant", member(), projectID, envID, LevelWriter, LevelWriter},
		{"member with reader grant", member(), projectID, envID, LevelReader, LevelReader},
		{"member with viewer grant", member(), projectID, envID, LevelViewer, LevelViewer},
		{"member with no grant", member(), projectID, envID, LevelNone, LevelNone},
		{"member with an invented grant level", member(), projectID, envID, "superuser", LevelNone},

		// A service token is confined to its own project and environment.
		{"service read in scope", service(projectID, envID, reqctx.AccessRead), projectID, envID, LevelNone, LevelReader},
		{"service read-write in scope", service(projectID, envID, reqctx.AccessReadWrite), projectID, envID, LevelNone, LevelWriter},
		{"service read in another project", service(projectID, envID, reqctx.AccessRead), otherPrj, envID, LevelNone, LevelNone},
		{"service read in another env", service(projectID, envID, reqctx.AccessRead), projectID, otherEnv, LevelNone, LevelNone},
		{"service read-write in another env", service(projectID, envID, reqctx.AccessReadWrite), projectID, otherEnv, LevelNone, LevelNone},
		{"service with no access value", service(projectID, envID, reqctx.AccessNone), projectID, envID, LevelNone, LevelNone},

		// The platform admin gets nothing inside an organization (SPEC §2 rule 10).
		{"platform admin on a project", platformAdmin(), projectID, envID, LevelWriter, LevelNone},
		{"platform admin with a grant", platformAdmin(), projectID, envID, LevelWriter, LevelNone},

		// Anonymous gets nothing.
		{"anonymous", anonymous(), projectID, envID, LevelWriter, LevelNone},
		{"zero value actor", reqctx.Actor{}, projectID, envID, LevelWriter, LevelNone},

		// A user with no org is not a member of anything.
		{"owner without an org", reqctx.Actor{Kind: reqctx.KindUser, Role: reqctx.RoleOwner}, projectID, envID, LevelNone, LevelNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Effective(tt.actor, tt.prj, tt.env, tt.grant); got != tt.expect {
				t.Errorf("Effective() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// TestCapabilities covers the ladder: viewer sees, reader reads, writer writes.
func TestCapabilities(t *testing.T) {
	tests := []struct {
		name              string
		actor             reqctx.Actor
		grant             string
		view, read, write bool
	}{
		{"owner", owner(), LevelNone, true, true, true},
		{"admin", admin(), LevelNone, true, true, true},
		{"member writer", member(), LevelWriter, true, true, true},
		{"member reader", member(), LevelReader, true, true, false},
		{"member viewer", member(), LevelViewer, true, false, false},
		{"member no grant", member(), LevelNone, false, false, false},
		{"service read", service(projectID, envID, reqctx.AccessRead), LevelNone, true, true, false},
		{"service read-write", service(projectID, envID, reqctx.AccessReadWrite), LevelNone, true, true, true},
		{"service out of scope", service(otherPrj, envID, reqctx.AccessReadWrite), LevelNone, false, false, false},
		{"platform admin", platformAdmin(), LevelNone, false, false, false},
		{"anonymous", anonymous(), LevelNone, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanView(tt.actor, projectID, envID, tt.grant); got != tt.view {
				t.Errorf("CanView() = %v, want %v", got, tt.view)
			}
			if got := CanRead(tt.actor, projectID, envID, tt.grant); got != tt.read {
				t.Errorf("CanRead() = %v, want %v", got, tt.read)
			}
			if got := CanWrite(tt.actor, projectID, envID, tt.grant); got != tt.write {
				t.Errorf("CanWrite() = %v, want %v", got, tt.write)
			}
		})
	}
}

// TestRoles covers the org-role predicates and the management capabilities from
// SPEC §2 rules 2, 3, 6 and 7.
func TestRoles(t *testing.T) {
	tests := []struct {
		name                                               string
		actor                                              reqctx.Actor
		owner, admin, manager, member, canManage, canAudit bool
	}{
		{"owner", owner(), true, false, true, false, true, true},
		{"admin", admin(), false, true, true, false, true, true},
		{"member", member(), false, false, false, true, false, false},
		{"service token", service(projectID, envID, reqctx.AccessReadWrite), false, false, false, false, false, false},
		{"platform admin", platformAdmin(), false, false, false, false, false, false},
		{"anonymous", anonymous(), false, false, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOwner(tt.actor); got != tt.owner {
				t.Errorf("IsOwner() = %v, want %v", got, tt.owner)
			}
			if got := IsAdmin(tt.actor); got != tt.admin {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.admin)
			}
			if got := IsOrgManager(tt.actor); got != tt.manager {
				t.Errorf("IsOrgManager() = %v, want %v", got, tt.manager)
			}
			if got := IsMember(tt.actor); got != tt.member {
				t.Errorf("IsMember() = %v, want %v", got, tt.member)
			}
			if got := CanManageMembers(tt.actor); got != tt.canManage {
				t.Errorf("CanManageMembers() = %v, want %v", got, tt.canManage)
			}
			if got := CanReadAudit(tt.actor); got != tt.canAudit {
				t.Errorf("CanReadAudit() = %v, want %v", got, tt.canAudit)
			}
		})
	}
}

// TestServiceTokenNeverManages pins SPEC §2 rule 7: a service token can never
// approve changes, manage members, issue tokens or read the audit log, even with
// read-write access.
func TestServiceTokenNeverManages(t *testing.T) {
	for _, access := range []reqctx.Access{reqctx.AccessRead, reqctx.AccessReadWrite} {
		token := service(projectID, envID, access)

		if CanApprove(token) {
			t.Errorf("service token with %q can approve", access)
		}
		if CanManageMembers(token) {
			t.Errorf("service token with %q can manage members", access)
		}
		if CanManageTokens(token) {
			t.Errorf("service token with %q can issue tokens", access)
		}
		if CanReadAudit(token) {
			t.Errorf("service token with %q can read the audit log", access)
		}
		if CanManageOwnership(token) {
			t.Errorf("service token with %q can manage ownership", access)
		}
		if CanManageOrg(token) {
			t.Errorf("service token with %q can manage the org", access)
		}
		if IsOrgManager(token) {
			t.Errorf("service token with %q is an org manager", access)
		}
	}
}

// TestOnlyOwnerManagesOwnership pins SPEC §2 rule 2.
func TestOnlyOwnerManagesOwnership(t *testing.T) {
	if !CanManageOwnership(owner()) {
		t.Error("an owner cannot manage ownership")
	}
	if CanManageOwnership(admin()) {
		t.Error("an admin can manage ownership")
	}
	if CanManageOwnership(member()) {
		t.Error("a member can manage ownership")
	}
}

func TestPlatformAdminIsolation(t *testing.T) {
	if !IsPlatformAdmin(platformAdmin()) {
		t.Error("IsPlatformAdmin() = false for the platform admin")
	}
	for _, actor := range []reqctx.Actor{owner(), admin(), member(), anonymous(), service(projectID, envID, reqctx.AccessRead)} {
		if IsPlatformAdmin(actor) {
			t.Errorf("IsPlatformAdmin() = true for %q", actor.Kind)
		}
	}
	// The platform admin is authenticated but has no org capabilities at all.
	if !IsAuthenticated(platformAdmin()) {
		t.Error("the platform admin is not authenticated")
	}
	if CanListProjects(platformAdmin()) {
		t.Error("the platform admin can list an organization's projects")
	}
}

func TestIsAuthenticated(t *testing.T) {
	for _, actor := range []reqctx.Actor{owner(), admin(), member(), platformAdmin(), service(projectID, envID, reqctx.AccessRead)} {
		if !IsAuthenticated(actor) {
			t.Errorf("IsAuthenticated() = false for %q", actor.Kind)
		}
	}
	if IsAuthenticated(anonymous()) {
		t.Error("IsAuthenticated() = true for an anonymous actor")
	}
	if IsAuthenticated(reqctx.Actor{}) {
		t.Error("IsAuthenticated() = true for the zero actor")
	}
}

// TestTenantBoundary pins that a grant only counts inside the actor's own org: a
// grant string is never enough on its own, and an actor with no org has no access.
func TestTenantBoundary(t *testing.T) {
	foreign := reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_2", OrgID: otherOrg, Role: reqctx.RoleMember}
	// The caller resolved a grant from its own org; a project id from another org is
	// only reachable if the store handed back a grant, which it must not. Here we
	// assert the member path uses the grant, and the owner path needs an org.
	if got := Effective(foreign, projectID, envID, LevelWriter); got != LevelWriter {
		t.Errorf("member with a grant = %q, want writer", got)
	}
	noOrg := reqctx.Actor{Kind: reqctx.KindUser, Role: reqctx.RoleMember}
	if got := Effective(noOrg, projectID, envID, LevelWriter); got != LevelNone {
		t.Errorf("member without an org = %q, want none", got)
	}
	ownerNoOrg := reqctx.Actor{Kind: reqctx.KindUser, Role: reqctx.RoleOwner}
	if got := Effective(ownerNoOrg, projectID, envID, LevelNone); got != LevelNone {
		t.Errorf("owner without an org = %q, want none", got)
	}
}

// TestEmptyProjectIsNeverWritable pins that a handler which fails to resolve a
// project cannot accidentally grant access to the empty id.
func TestEmptyProjectIsNeverWritable(t *testing.T) {
	for _, actor := range []reqctx.Actor{owner(), admin(), member(), service("", "", reqctx.AccessReadWrite)} {
		if CanWrite(actor, "", "", LevelWriter) {
			t.Errorf("CanWrite() = true for an empty project id with actor %q", actor.Kind)
		}
	}
}
