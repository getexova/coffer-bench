package authstore

import "context"

// Grant levels (SPEC §1, §2.4).
const (
	LevelViewer = "viewer"
	LevelReader = "reader"
	LevelWriter = "writer"
)

// Grant gives one member access to one project. Owners and admins never need a
// grant; they see every project in their organization.
type Grant struct {
	ProjectID string
	UserID    string
	Level     string
}

// SetGrant creates or replaces a grant. The level is replaced in place, which is
// how "grant revoked or lowered" becomes visible on the next request: resolution
// reads the level from this row every time, and nothing is cached.
func SetGrant(ctx context.Context, q Querier, projectID, userID, level string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO project_grants (project_id, user_id, level) VALUES ($1, $2, $3)
		 ON CONFLICT (project_id, user_id) DO UPDATE SET level = EXCLUDED.level`,
		projectID, userID, level)
	return mapErr(err)
}

// DeleteGrant removes a grant. It reports whether a row was removed so the caller
// can decide whether the request was a no-op.
func DeleteGrant(ctx context.Context, q Querier, projectID, userID string) (bool, error) {
	tag, err := q.Exec(ctx,
		`DELETE FROM project_grants WHERE project_id = $1 AND user_id = $2`, projectID, userID)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}

// GrantLevel returns the user's grant level on one project, or ErrNotFound when
// there is none.
func GrantLevel(ctx context.Context, q Querier, projectID, userID string) (string, error) {
	var level string
	err := q.QueryRow(ctx,
		`SELECT level FROM project_grants WHERE project_id = $1 AND user_id = $2`,
		projectID, userID).Scan(&level)
	return level, mapErr(err)
}

// GrantOnSlug resolves a project by slug inside the caller's organization and
// returns the caller's grant level on it in one statement. Zero rows means either
// the project does not exist in this organization or the user holds no grant, and
// the two are deliberately indistinguishable to the caller.
func GrantOnSlug(ctx context.Context, q Querier, orgID, userID, slug string) (Project, string, error) {
	var (
		p     Project
		level string
	)
	err := q.QueryRow(ctx,
		`SELECT p.id, p.org_id, p.slug, p.created_at, g.level
		   FROM projects p
		   JOIN project_grants g ON g.project_id = p.id AND g.user_id = $2
		  WHERE p.org_id = $1 AND p.slug = $3`, orgID, userID, slug).
		Scan(&p.ID, &p.OrgID, &p.Slug, &p.CreatedAt, &level)
	return p, level, mapErr(err)
}
