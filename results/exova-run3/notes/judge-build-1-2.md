# Judge 2, build-1: E2, E4, E5

## What I did
- Cloned build-1.bundle into a laptop temp dir (/tmp/tmp.N4vf9x8qIP/b1; HEAD b542644). Read tests and docs only. Executed nothing from the build. Did not use the VM.
- Read GRADER.md and SPEC.md (§ on required docs), plus results/build-1/r2 (results.jsonl, logs for X2, X4, A6, S16, E1). Used the resolved status table I was given.

## E2: PASS
Authorization tests exist and ran: E1 r2 test.sh started a throwaway postgres:16 and ran `go test -p 1 ./...`, so the DB-backed tests ran and were not skipped. authapi 4.5s and secretsapi 27.4s, both ok.
- Cross-org 404:
  - internal/api/authapi/authz_db_test.go TestInvisibleIs404: an org-B member asks for org-A's project, which has the same slug. Gets 404, and the body is byte-identical to the 404 for a project that does not exist.
  - internal/api/secretsapi/secrets_test.go TestUnknownProjectIs404: another org's owner gets 404 on the same slug.
  - internal/authz/authz_test.go TestTenantBoundary.
- Two-person rule:
  - secrets_test.go TestSelfApprovalIs403: the owner proposes and then self-approves. Gets 403 and the change request stays pending.
  - TestServiceTokenIssuerCannotApproveOwnProposal: the token's issuer gets 403, and a different admin gets 200 and the change applies.
  - TestProtectedWriteReturns202: approval by the admin applies the change.
- Other authorization tests: TestMemberCannotApprove, TestMemberWithoutGrantIs404, and in authz_db_test.go TestNoSelfEscalation, TestMemberAndServiceTokenCannotManage, TestPlatformAdminSeesNothing, TestLastOwnerRules. Also internal/authz/authz_test.go.

## E4: PASS
docs/SECURITY.md has sections for Assets (5 items), Actors (a table of 7), Trust boundaries (6), Master key handling, Known limitations (9 items), plus What is not protected and Out of scope.

Claims compared with the resolved suite results:
- Consistent with the suite:
  - Master-key refusal (placeholder, wrong length, missing): G3 and X3 pass.
  - Argon2id hashing: X5 pass.
  - Identical login for unknown email and wrong password: X7 pass.
  - Lockout after 5 failures: X8 pass.
  - Revocation with no cache: S17, S18 and X13 pass.
  - Password on stdin only: X14 pass.
  - Invisible resources return 404: S1, S3, S5 and S14 pass.
  - Denials audited in the actor's org: A2 pass.
  - No self-escalation: S13 pass.
  - Platform admin sees no org data: S4 pass.
  - Runtime role cannot modify audit rows: X19 pass.
  - Non-root container: O2 pass. Pinned image: O9 pass.
  - Hash chain detects modification: A5 pass.
  - Master key absent from DB, logs and backups: X1 pass.
- Checks the suite failed:
  - X4 (pending void review): with the old key alone the server starts and reads return 500. That is fail-closed, and the doc only promises refusal for a missing, short or placeholder key. No contradiction.
  - X2 (pending void review): tampered ciphertext gives 500 and no value. SECURITY.md makes no AAD claim; ARCHITECTURE.md says this case returns 500.
  - A6 (pending void review): after a mid-chain delete, verify reports the deleted seq, not the next one. The doc claims a delete breaks the chain and that verify reports the first invalid seq. Verify did exit 9.
  - S16 (pending void review): /auth/token with a service-token bearer and valid user credentials returns a PAT. The route is unauthenticated by spec; no contradiction with the doc's service-token scope claim.
  - X10, X11, F3, O4: no SECURITY.md claim covers them.
- If a void review upholds A6, the one arguable tension is the phrase "verify reports the first invalid sequence number". That check is under void review.

## E5: PASS
docs/DECISIONS.md exists (488 lines). I spot-checked docs/ARCHITECTURE.md against the code, and these claims match:
- one binary with `serve` (cmd/coffer/main.go)
- ServeMux with one Register per slice (internal/httpapi/router.go)
- the package table matches the internal/ tree
- 1 MiB body limit (httpx.MaxBodyBytes = 1<<20)
- "internal error" message for panics and 500s
- X-Request-Id, and JSON request logs with method, route, status, duration_ms and request_id
- AAD domains coffer:v1, coffer:dek:v1 and coffer:change:v1 with uvarint length prefixes (crypto/aad.go)
- AES-256-GCM
- the `current_version = current_version + 1` allocator (store/secrets/write.go)
- approve order: self-check, then CAS on status='pending', then FOR UPDATE, then stale (store/secrets/changes.go)
- audit_heads FOR UPDATE, SHA-256, SetEscapeHTML(false), microsecond timestamps
- go:embed migrations, pg_advisory_lock, schema_migrations checksums
- coffer_app gets SELECT,INSERT on audit_events, plus triggers that raise for non-superusers
- the data-model tables match 0001_init.sql
- testutil mints a PAT via /auth/token

Minor imprecision: ARCHITECTURE.md says every request gets a log line, but the code wraps only the /api/v1 mux, so out-of-surface paths are not logged (this matches the O4 failure). This does not change the verdict.

No secrets recorded in this note.
