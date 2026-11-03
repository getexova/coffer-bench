package authstore

import (
	"context"
	"time"
)

// Env is one environment of one project. Protected environments turn any write
// into a change request (SPEC §2.8), which the secrets slice enforces.
type Env struct {
	ID        string
	ProjectID string
	Slug      string
	Protected bool
	CreatedAt time.Time
}

const envCols = `id, project_id, slug, protected, created_at`

func scanEnv(row pgxRow) (Env, error) {
	var e Env
	err := row.Scan(&e.ID, &e.ProjectID, &e.Slug, &e.Protected, &e.CreatedAt)
	return e, mapErr(err)
}

// CreateEnv inserts an environment. A duplicate slug inside the project is
// ErrConflict.
func CreateEnv(ctx context.Context, q Querier, id, projectID, slug string, protected bool) (Env, error) {
	return scanEnv(q.QueryRow(ctx,
		`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, $3, $4)
		 RETURNING `+envCols, id, projectID, slug, protected))
}

// EnvBySlug reads one environment of one project. The project id is part of the
// predicate, so an environment of another project is indistinguishable from a
// missing one.
func EnvBySlug(ctx context.Context, q Querier, projectID, slug string) (Env, error) {
	return scanEnv(q.QueryRow(ctx,
		`SELECT `+envCols+` FROM environments WHERE project_id = $1 AND slug = $2`, projectID, slug))
}

// EnvByID reads one environment of one project.
func EnvByID(ctx context.Context, q Querier, projectID, envID string) (Env, error) {
	return scanEnv(q.QueryRow(ctx,
		`SELECT `+envCols+` FROM environments WHERE project_id = $1 AND id = $2`, projectID, envID))
}

// ListEnvs lists every environment of one project, ordered by slug.
func ListEnvs(ctx context.Context, q Querier, projectID string) ([]Env, error) {
	rows, err := q.Query(ctx,
		`SELECT `+envCols+` FROM environments WHERE project_id = $1 ORDER BY slug`, projectID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (Env, error) { return scanEnv(r) })
}
