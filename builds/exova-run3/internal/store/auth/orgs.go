package authstore

import (
	"context"
	"time"
)

// Org is one tenant. Slug is globally unique (organizations.slug UNIQUE), which
// is the only global uniqueness in the schema; project slugs are per-org.
type Org struct {
	ID         string
	Slug       string
	CreatedAt  time.Time
	DisabledAt *time.Time
}

const orgCols = `id, slug, created_at, disabled_at`

func scanOrg(row pgxRow) (Org, error) {
	var o Org
	err := row.Scan(&o.ID, &o.Slug, &o.CreatedAt, &o.DisabledAt)
	return o, mapErr(err)
}

// CreateOrg inserts one organization.
func CreateOrg(ctx context.Context, q Querier, id, slug string) (Org, error) {
	return scanOrg(q.QueryRow(ctx,
		`INSERT INTO organizations (id, slug) VALUES ($1, $2) RETURNING `+orgCols, id, slug))
}

// OrgByID reads one organization by id.
func OrgByID(ctx context.Context, q Querier, id string) (Org, error) {
	return scanOrg(q.QueryRow(ctx,
		`SELECT `+orgCols+` FROM organizations WHERE id = $1`, id))
}

// OrgBySlug reads one organization by slug.
func OrgBySlug(ctx context.Context, q Querier, slug string) (Org, error) {
	return scanOrg(q.QueryRow(ctx,
		`SELECT `+orgCols+` FROM organizations WHERE slug = $1`, slug))
}

// ListOrgs returns every organization, newest last, for the platform admin.
func ListOrgs(ctx context.Context, q Querier) ([]Org, error) {
	rows, err := q.Query(ctx, `SELECT `+orgCols+` FROM organizations ORDER BY created_at, id`)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (Org, error) { return scanOrg(r) })
}

// DisableOrg sets disabled_at once. It reports whether this call performed the
// transition; a second call on an already-disabled organization is a no-op and
// reports false, which lets the API stay idempotent without a second audit
// event. A disabled organization fails token resolution immediately (see
// ResolveTokenSQL), which is what makes §2.11 hold.
func DisableOrg(ctx context.Context, q Querier, id string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE organizations SET disabled_at = now() WHERE id = $1 AND disabled_at IS NULL`, id)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}
