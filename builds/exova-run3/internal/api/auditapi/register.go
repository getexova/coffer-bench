// Package auditapi owns the audit read routes: GET /audit, GET /audit/verify, and
// the platform log at GET /admin/audit and GET /admin/audit/verify
// (docs/CONTRACTS.md §4).
//
// Every route here is a read. Nothing in this package appends, updates or deletes:
// the only writer in the audit slice is audit.Appender, and verification must not
// modify the thing it is verifying.
//
// Authorization is two-sided and the asymmetry is deliberate:
//
//   - The organization routes belong to the tenant. An owner or admin reads them; a
//     plain member is refused with 403 because the resource is visible to them and
//     they lack the permission (SPEC §2 rule 6). The platform admin gets 404, not
//     403, because every organization-scoped route is invisible to it (SPEC §2
//     rule 10) — and the 404 body is identical to the one for a route that does not
//     exist, so it reveals nothing about whether the organization has a log.
//
//   - The platform routes belong to the platform admin alone. Anyone else gets 403:
//     the platform log is not a tenant resource, so there is no invisibility rule to
//     apply and 404 would only mislead.
package auditapi

import (
	"log/slog"
	"net/http"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/store"
)

// apiPrefix is the frozen API prefix. Register binds full patterns including it.
const apiPrefix = "/api/v1"

// Deps is what the audit slice receives from the composition root.
type Deps struct {
	DB     *store.DB
	Audit  audit.Writer
	Config *config.Config
	Log    *slog.Logger
}

// Register installs the audit slice's routes on mux.
func Register(mux *http.ServeMux, deps Deps) {
	a := newAPI(deps)

	// Organization audit log: owners and admins only.
	mux.HandleFunc("GET "+apiPrefix+"/audit", a.handleOrgAudit)
	mux.HandleFunc("GET "+apiPrefix+"/audit/verify", a.handleOrgAuditVerify)

	// Platform audit log: the platform admin only.
	mux.HandleFunc("GET "+apiPrefix+"/admin/audit", a.handlePlatformAudit)
	mux.HandleFunc("GET "+apiPrefix+"/admin/audit/verify", a.handlePlatformAuditVerify)
}
