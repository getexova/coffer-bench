// Package authz holds Coffer's visibility and capability rules as pure
// predicates: no database, no network, no clock, no context.
//
// Keeping them pure is what makes SPEC §2 testable without a server. A handler
// resolves the caller's grant from the store and then asks this package what that
// grant means; the decision itself never depends on anything else, so a reviewer
// can read every rule in one file.
//
// The rules, from SPEC §2 and docs/CONTRACTS.md §1:
//
//   - The platform admin gets nothing inside an organization. Every org-scoped
//     route returns 404 for it, so it is not "denied" here; it is invisible.
//   - An anonymous caller gets nothing.
//   - A service token is confined to its own project and environment, and maps
//     read to reader and read-write to writer. It can never manage anything.
//   - An owner or admin reaches every project in their organization without a
//     grant. A member reaches only a project it has a grant for.
package authz

import "coffer/internal/reqctx"

// Grant levels, as stored in project_grants.level.
const (
	LevelNone   = ""
	LevelViewer = "viewer"
	LevelReader = "reader"
	LevelWriter = "writer"
)

// rank orders the grant levels. Viewer sees names and metadata, reader also sees
// values, writer also changes them; each level includes the ones below it.
func rank(level string) int {
	switch level {
	case LevelViewer:
		return 1
	case LevelReader:
		return 2
	case LevelWriter:
		return 3
	default:
		return 0
	}
}

// Effective returns the level actor holds on projectID/envID given the caller's
// stored grant: LevelNone, LevelViewer, LevelReader or LevelWriter.
//
// grant is the level from project_grants for this actor and project, or "" when
// there is none. A caller that does not know the grant yet must pass "" — the
// answer is then "no access", never "full access".
func Effective(actor reqctx.Actor, projectID, envID, grant string) string {
	switch actor.Kind {
	case reqctx.KindUser:
		switch actor.Role {
		case reqctx.RoleOwner, reqctx.RoleAdmin:
			// Owners and admins reach every project in their own org. The org
			// check is not redundant: it is the tenant boundary.
			if actor.OrgID == "" || projectID == "" {
				return LevelNone
			}
			return LevelWriter
		case reqctx.RoleMember:
			if actor.OrgID == "" || projectID == "" {
				return LevelNone
			}
			return normalise(grant)
		default:
			return LevelNone
		}

	case reqctx.KindService:
		// A service token is confined to exactly one project and one
		// environment. Any other target is invisible.
		if projectID == "" || envID == "" {
			return LevelNone
		}
		if actor.ProjectID == "" || actor.EnvID == "" {
			return LevelNone
		}
		if actor.ProjectID != projectID || actor.EnvID != envID {
			return LevelNone
		}
		switch actor.Access {
		case reqctx.AccessRead:
			return LevelReader
		case reqctx.AccessReadWrite:
			return LevelWriter
		default:
			return LevelNone
		}

	default:
		// Platform admin, anonymous, and anything unrecognised.
		return LevelNone
	}
}

func normalise(level string) string {
	switch level {
	case LevelViewer, LevelReader, LevelWriter:
		return level
	default:
		return LevelNone
	}
}

// CanView reports whether the caller may see secret names and metadata.
func CanView(actor reqctx.Actor, projectID, envID, grant string) bool {
	return rank(Effective(actor, projectID, envID, grant)) >= rank(LevelViewer)
}

// CanRead reports whether the caller may read values, export and use run.
func CanRead(actor reqctx.Actor, projectID, envID, grant string) bool {
	return rank(Effective(actor, projectID, envID, grant)) >= rank(LevelReader)
}

// CanWrite reports whether the caller may set, delete and roll back.
func CanWrite(actor reqctx.Actor, projectID, envID, grant string) bool {
	return rank(Effective(actor, projectID, envID, grant)) >= rank(LevelWriter)
}

// CanList reports whether the caller may list the projects of its organization.
// It is CanView for a single project; the platform admin and a service token
// cannot list an org's projects.
func CanListProjects(actor reqctx.Actor) bool {
	if actor.Kind != reqctx.KindUser || actor.OrgID == "" {
		return false
	}
	switch actor.Role {
	case reqctx.RoleOwner, reqctx.RoleAdmin, reqctx.RoleMember:
		return true
	default:
		return false
	}
}

// IsOwner reports whether the caller is an organization owner.
func IsOwner(actor reqctx.Actor) bool {
	return actor.Kind == reqctx.KindUser && actor.Role == reqctx.RoleOwner && actor.OrgID != ""
}

// IsAdmin reports whether the caller is an organization admin.
func IsAdmin(actor reqctx.Actor) bool {
	return actor.Kind == reqctx.KindUser && actor.Role == reqctx.RoleAdmin && actor.OrgID != ""
}

// IsOrgManager reports whether the caller may manage the organization: an owner
// or an admin. A service token is never an org manager.
func IsOrgManager(actor reqctx.Actor) bool {
	return IsOwner(actor) || IsAdmin(actor)
}

// IsMember reports whether the caller is an organization member.
func IsMember(actor reqctx.Actor) bool {
	return actor.Kind == reqctx.KindUser && actor.Role == reqctx.RoleMember && actor.OrgID != ""
}

// CanManageMembers reports whether the caller may add, remove or re-role members
// and set or revoke grants (SPEC §2 rule 3). It is true for owners and admins;
// which members each of them may touch is the caller's problem, because only an
// owner may touch an owner.
func CanManageMembers(actor reqctx.Actor) bool { return IsOrgManager(actor) }

// CanManageTokens reports whether the caller may issue and revoke service tokens.
func CanManageTokens(actor reqctx.Actor) bool { return IsOrgManager(actor) }

// CanReadAudit reports whether the caller may read the organization audit log.
// A service token can never read it (SPEC §2 rule 7).
func CanReadAudit(actor reqctx.Actor) bool { return IsOrgManager(actor) }

// CanApprove reports whether the caller may approve or reject a change request.
// The two-person rule — the approver is not the proposer — needs the change's
// proposer, so it is checked where the change is loaded, not here.
func CanApprove(actor reqctx.Actor) bool { return IsOrgManager(actor) }

// CanManageOwnership reports whether the caller may create an owner, promote
// someone to owner, demote an owner or remove an owner. Only an owner can.
func CanManageOwnership(actor reqctx.Actor) bool { return IsOwner(actor) }

// IsPlatformAdmin reports whether the caller is the platform admin. The platform
// admin reaches only /admin/* and the platform audit log; every organization-scoped
// route must answer 404 for it.
func IsPlatformAdmin(actor reqctx.Actor) bool {
	return actor.Kind == reqctx.KindPlatform && actor.Role == reqctx.RolePlatformAdmin
}

// IsAuthenticated reports whether the request carries a resolved credential. A
// route that is not public must answer 401 before it asks any other question.
func IsAuthenticated(actor reqctx.Actor) bool {
	switch actor.Kind {
	case reqctx.KindUser, reqctx.KindService, reqctx.KindPlatform:
		return true
	default:
		return false
	}
}

// CanManageOrg reports whether the caller may act on the organization as a whole,
// such as creating a project or an environment. Service tokens cannot.
func CanManageOrg(actor reqctx.Actor) bool { return IsOrgManager(actor) }
