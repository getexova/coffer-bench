package secretsapi

import (
	"coffer/internal/store/secrets"
)

// handler carries the slice's dependencies to each route.
type handler struct {
	deps  Deps
	store *secrets.Store
}
