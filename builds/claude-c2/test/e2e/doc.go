// Package e2e holds Coffer's black-box end-to-end tests. They drive a running
// stack only through the fixed interfaces (the coffer CLI binary and the HTTP
// API) and are compiled only with the "e2e" build tag:
//
//	COFFER_E2E_CLI=$PWD/bin/coffer go test -tags e2e -count=1 ./test/e2e/...
//
// Environment:
//
//	COFFER_E2E_URL             server base URL (default http://127.0.0.1:8420)
//	COFFER_E2E_CLI             path to the coffer binary (default ../../bin/coffer)
//	COFFER_E2E_ADMIN_EMAIL     platform admin email (default admin@example.com)
//	COFFER_E2E_ADMIN_PASSWORD  platform admin password (default: read
//	                           COFFER_BOOTSTRAP_ADMIN_PASSWORD from ../../.env)
//
// Every run uses fresh random organization slugs and emails, so the suite can
// run repeatedly against the same stack.
package e2e
