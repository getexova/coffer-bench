# Judge 1, build-1: E2, E4, E5

What I did: cloned build-1.bundle into /tmp/judge-b1-jQ02/b1 and read its tests and docs (docs/SECURITY.md, docs/ARCHITECTURE.md, docs/DECISIONS.md) plus the code paths that ARCHITECTURE.md names. I ran none of the build's code. I compared SECURITY.md's claims with the resolved r2 results for build-1. I did not open build-2, the VM, or any sealed path. No secrets appear in this note.

## E2: PASS
- Cross-org 404:
  - internal/api/authapi/authz_db_test.go TestInvisibleIs404: a member of org B requests org A's project with the same slug and gets 404, with a body byte-identical to the 404 for a nonexistent project. A member with no grant in their own org also gets 404.
  - internal/api/secretsapi/secrets_test.go: TestUnknownProjectIs404 (another org's project gives 404) and TestMemberWithoutGrantIs404.
  - internal/authz/authz_test.go: TestTenantBoundary and TestPlatformAdminIsolation.
  - internal/api/authapi/authz_db_test.go TestPlatformAdminSeesNothing.
- Two-person rule:
  - secrets_test.go TestSelfApprovalIs403: the owner who proposed gets 403 on approve, and the CR stays pending.
  - secrets_test.go TestServiceTokenIssuerCannotApproveOwnProposal: the issuer gets 403 and a different admin's approval returns 200.
  - secrets_test.go also has TestMemberCannotApprove, TestDoubleApproveIs409ThroughHTTP and TestStaleApprovalIs409ThroughHTTP.
- Other authorization tests:
  - authz_db_test.go: TestNoSelfEscalation, TestLastOwnerRules, TestMemberAndServiceTokenCannotManage, TestRevocationIsImmediate.
  - authz_test.go: TestServiceTokenNeverManages, TestOnlyOwnerManagesOwnership.
- The DB tests skip without COFFER_TEST_DATABASE_URL. scripts/test.sh starts a postgres:16 container for them, and E1 passed (r2).

## E4: PASS
SECURITY.md has sections for each required item:
- Assets (5)
- Actors (a table of 7)
- Trust boundaries (6)
- Master key handling
- Known limitations
- Also: what is not protected, and out of scope.

Claims checked against resolved results:

| Claim | Result |
|---|---|
| Placeholder, wrong-length or missing key is refused | X3, G3 pass |
| Key never in the DB, logs, audit or backup | X1 pass |
| argon2id hashing | X5 pass |
| Login has identical status, body and timing | X7 pass |
| Lockout | X8 pass |
| Tokens stored as hashes only | X6 pass |
| Revocation takes effect on the next request | S17, X13 pass |
| Passwords on stdin, never in argv | X14 pass |
| Invisible resource is 404 | S1, S3, S5 pass |
| Denials are audited in the actor's chain | A2 pass |
| No self-escalation; last owner gets 409 | S13, S12 pass |
| Runtime role cannot UPDATE or DELETE audit rows | X19 pass |
| Hash chain detects modification | A4, A5 pass |
| Non-root server in a pinned image | O2, O9 pass |
| Platform admin cannot read org data | S4 pass |

No resolved result contradicts a SECURITY.md claim. Notes on the failing rows:
- X4 (fail-pending-void-review): with MASTER=old alone the server reports ready, then reads return 500 with no value. SECURITY.md promises refusal only for a missing, wrong-length or placeholder key, and says rotation re-wraps before ready. It makes no claim about a stale key, so I see no contradiction. If someone reads the claim "after which the old key is not needed" as implying the old key fails closed at startup, then this pending check is the only basis for an E4 failure.
- X2 (fail-pending-void-review): tampered rows return 500, not a value. SECURITY.md makes no AAD claim. ARCHITECTURE.md says a tag failure gives "500 with no value", which is consistent with this.
- S16 (fail-pending-void-review): /auth/token ignores a service-token bearer when the request also carries valid user credentials. This is not a service-token capability, and it does not contradict "secret operations inside one project and one environment".
- A6 (fail-pending-void-review): reports first_invalid_seq at the deleted seq rather than the next seq. SECURITY.md only says deletion is detected and the first invalid seq is reported, so there is no contradiction.
- F3, X10, X11, O4: SECURITY.md makes no claim about these (bad-key exit code, a NUL byte in the path giving 500, the out-of-surface request log).

## E5: PASS
docs/DECISIONS.md exists (488 lines, sectioned). I spot-checked docs/ARCHITECTURE.md against the code, and these claims match:
- The package table matches the tree.
- router.go is the composition root, calling authapi, secretsapi and auditapi Register, with the central denial flush.
- AAD domains coffer:v1, coffer:dek:v1 and coffer:change:v1 use uvarint length prefixes (internal/crypto/aad.go).
- Allocator: `UPDATE secrets SET current_version = current_version + 1 ... RETURNING` (internal/store/secrets/write.go).
- CR approval CAS, then `FOR UPDATE` on the secret row, then stale (internal/store/secrets/changes.go).
- Audit append takes `audit_heads FOR UPDATE`, canonical JSON with SetEscapeHTML(false), and SHA-256. Verify does not trust audit_heads.
- coffer_app has only SELECT and INSERT on audit_events, and triggers stop non-superusers (grants.sql, 0001_init.sql).
- Migrations: go:embed, pg_advisory_lock, and schema_migrations checksums.
- Rotation runs before ready (internal/httpapi/server.go).
- Body limit is 1 MiB, and errors carry the literal "internal error" (httpx).
- Data-model tables match 0001_init.sql.

One minor drift: the doc says every request gets a JSON log line, but O4 found no line for an out-of-surface path. This is not material to E5.
