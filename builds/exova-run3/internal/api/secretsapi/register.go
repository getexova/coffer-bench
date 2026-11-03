// Package secretsapi owns the secret, version, export and change-request routes:
// /projects/{p}/envs/{e}/secrets, its {key} and /versions children, /rollback,
// /export, and /changes with /changes/{id}/approve and /changes/{id}/reject
// (docs/CONTRACTS.md §4).
//
// The package is organised around three rules that are visible in the file layout:
//
//   - common.go resolves a project and environment, then authorises. Resolution puts org_id in the
//     SQL predicate, so a resource in another organization and a resource that does not exist are
//     the same 404.
//   - secrets.go holds the plaintext exits: a single-key get (current or historical) and an export,
//     which `run` uses. Each writes one audit event per key read.
//   - changes.go holds the two-person rule: propose, approve, reject.
//
// No handler re-parses Authorization; the middleware has already put the actor in the context and
// rejected a bad credential with 401.
package secretsapi

import (
	"log/slog"
	"net/http"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/crypto"
	"coffer/internal/httpx"
	"coffer/internal/store"
	"coffer/internal/store/secrets"
)

// Deps is what the secrets slice receives from the composition root.
//
// The field set is frozen: internal/httpapi/router.go constructs it and never learns a new field.
type Deps struct {
	DB     *store.DB
	Audit  audit.Writer
	Config *config.Config
	Log    *slog.Logger
}

// Register installs the secrets slice's routes on mux. Patterns are full paths
// including the /api/v1 prefix; parameters are read with r.PathValue.
//
// The envelope sealer is built here from the validated master key, so a Store handed to a handler
// always has working cryptography behind it. config.Load has already refused a master key that is
// missing, not base64, or not 32 bytes, so a failure at this point is not reachable through the
// supported configuration path; if it does happen, every route fails closed with a 500 rather than
// serving values through a sealer that cannot authenticate them.
func Register(mux *http.ServeMux, deps Deps) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Audit == nil {
		deps.Audit = audit.NopWriter()
	}

	sealer, err := crypto.NewSealerFromBytes(deps.Config.MasterKey)
	if err != nil {
		// Never serve secrets without working cryptography. The message names no key material.
		deps.Log.Error("secretsapi: master key unusable; secrets routes are disabled", "error", err)
		h := &handler{deps: deps}
		for _, route := range routes {
			mux.HandleFunc(route.pattern, h.unavailable)
		}
		return
	}

	h := &handler{
		deps:  deps,
		store: secrets.New(store.NewBase(deps.DB), sealer),
	}
	for _, route := range routes {
		mux.HandleFunc(route.pattern, route.handle(h))
	}
}

// route is one registered route. Keeping the table in one place means the frozen interface is
// readable in a single screen and a wrong method is registered explicitly (ServeMux then answers
// 404 for it, which is what the status table requires).
type route struct {
	pattern string
	handle  func(*handler) http.HandlerFunc
}

// routes is the frozen route table for this slice (docs/CONTRACTS.md §4).
var routes = []route{
	// Secrets, in the environment of a project.
	{"GET /api/v1/projects/{p}/envs/{e}/secrets", func(h *handler) http.HandlerFunc { return h.list }},
	{"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}", func(h *handler) http.HandlerFunc { return h.get }},
	{"PUT /api/v1/projects/{p}/envs/{e}/secrets/{key}", func(h *handler) http.HandlerFunc { return h.set }},
	{"DELETE /api/v1/projects/{p}/envs/{e}/secrets/{key}", func(h *handler) http.HandlerFunc { return h.remove }},
	{"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}/versions", func(h *handler) http.HandlerFunc { return h.history }},
	{"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}/versions/{n}", func(h *handler) http.HandlerFunc { return h.versionAt }},
	{"POST /api/v1/projects/{p}/envs/{e}/secrets/{key}/rollback", func(h *handler) http.HandlerFunc { return h.rollback }},
	{"GET /api/v1/projects/{p}/envs/{e}/export", func(h *handler) http.HandlerFunc { return h.export }},

	// Change requests for protected environments.
	{"GET /api/v1/changes", func(h *handler) http.HandlerFunc { return h.listChanges }},
	{"POST /api/v1/changes/{id}/approve", func(h *handler) http.HandlerFunc { return h.approve }},
	{"POST /api/v1/changes/{id}/reject", func(h *handler) http.HandlerFunc { return h.reject }},
}

// unavailable answers every secrets route when the process has no usable master key. It is a
// refusal, not a stub: the alternative would be serving values through a sealer that cannot
// authenticate a ciphertext.
func (h *handler) unavailable(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, httpx.Internal(errMasterKeyUnusable))
}

// errMasterKeyUnusable is the cause logged for a disabled slice. It carries no key material.
var errMasterKeyUnusable = errNoMasterKey{}

type errNoMasterKey struct{}

func (errNoMasterKey) Error() string { return "secretsapi: master key unusable" }
