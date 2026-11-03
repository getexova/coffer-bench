package authstore

import (
	"context"
	"time"
)

// Project belongs to exactly one organization. Slug is unique per organization
// only (UNIQUE (org_id, slug)), never globally: a global uniqueness check would
// let one tenant probe another tenant's project names.
type Project struct {
	ID        string
	OrgID     string
	Slug      string
	CreatedAt time.Time
}

const projectCols = `id, org_id, slug, created_at`

func scanProject(row pgxRow) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.OrgID, &p.Slug, &p.CreatedAt)
	return p, mapErr(err)
}

// CreateProject inserts a project inside one organization. A duplicate slug in
// the same organization is ErrConflict; the same slug in another organization is
// not, and must never be reported as a conflict.
func CreateProject(ctx context.Context, q Querier, id, orgID, slug string) (Project, error) {
	return scanProject(q.QueryRow(ctx,
		`INSERT INTO projects (id, org_id, slug) VALUES ($1, $2, $3) RETURNING `+projectCols,
		id, orgID, slug))
}

// ProjectBySlug reads one project of one organization. The org id is part of the
// predicate so another tenant's project is the same zero-row result as a missing
// one.
func ProjectBySlug(ctx context.Context, q Querier, orgID, slug string) (Project, error) {
	return scanProject(q.QueryRow(ctx,
		`SELECT `+projectCols+` FROM projects WHERE org_id = $1 AND slug = $2`, orgID, slug))
}

// ProjectByID reads one project of one organization.
func ProjectByID(ctx context.Context, q Querier, orgID, projectID string) (Project, error) {
	return scanProject(q.QueryRow(ctx,
		`SELECT `+projectCols+` FROM projects WHERE org_id = $1 AND id = $2`, orgID, projectID))
}

// ListProjects lists every project of one organization, for owners and admins.
func ListProjects(ctx context.Context, q Querier, orgID string) ([]Project, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectCols+` FROM projects WHERE org_id = $1 ORDER BY slug`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (Project, error) { return scanProject(r) })
}

// ListProjectsForMember lists the projects of one organization the user holds a
// grant on. A member with no grant sees an empty list, not an error, and never
// learns that other projects exist.
func ListProjectsForMember(ctx context.Context, q Querier, orgID, userID string) ([]Project, error) {
	rows, err := q.Query(ctx,
		`SELECT p.id, p.org_id, p.slug, p.created_at
		   FROM projects p
		   JOIN project_grants g ON g.project_id = p.id AND g.user_id = $2
		  WHERE p.org_id = $1
		  ORDER BY p.slug`, orgID, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (Project, error) { return scanProject(r) })
}
