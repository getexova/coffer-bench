package secrets

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/audit"
	"coffer/internal/idgen"
)

// Change request statuses, matching the change_requests.status check in the frozen schema.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusStale    = "stale"
)

// ValidStatus reports whether s is a status the list filter accepts.
func ValidStatus(s string) bool {
	switch s {
	case StatusPending, StatusApproved, StatusRejected, StatusStale:
		return true
	}
	return false
}

// Change is a change_requests row. The proposed value is only ever held as ciphertext here.
type Change struct {
	ID            string
	OrgID         string
	ProjectID     string
	EnvID         string
	SecretID      string
	Key           string
	Op            Op
	PayloadCT     []byte
	PayloadNonce  []byte
	BaseVersion   int64
	TargetVersion *int64
	Status        string
	ProposerID    string
	CreatedAt     time.Time
	ResolvedAt    *time.Time
	ResolverID    string

	// ProjectSlug and EnvSlug come from the join, so the change list can address the resource
	// the way the API and the CLI do without a second lookup per row.
	ProjectSlug string
	EnvSlug     string
}

// ChangeTarget is the audit target for a change request event.
func ChangeTarget(id string) string { return id }

// SecretTarget is the audit target for a secret event: project, environment and key, so a row can
// be joined to the secret it describes without a second lookup.
func SecretTarget(projectID, envID, key string) string {
	return projectID + "/" + envID + "/" + key
}

// Proposal is a write to a protected environment that is waiting for a second person.
type Proposal struct {
	Scope     Scope
	Key       string
	Op        Op
	Value     []byte // OpSet only
	TargetVer int64  // OpRollback only
	BaseVer   int64
	Proposer  ActorRef
}

// CreateChange seals the proposed value under associated data bound to the new change id and
// inserts the row, in one transaction. Callers that also need to write the change.created audit
// event use CreateChangeTx so the event commits with the row.
func (s *Store) CreateChange(ctx context.Context, p Proposal) (Change, error) {
	var ch Change
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		ch, err = s.CreateChangeTx(ctx, tx, p)
		return err
	})
	if err != nil {
		return Change{}, err
	}
	return ch, nil
}

// CreateChangeTx inserts a pending change inside the caller's transaction.
//
// The order matters: the id is generated first because the associated data includes it, so the
// ciphertext is bound to this request before the row exists and cannot be redirected afterwards.
func (s *Store) CreateChangeTx(ctx context.Context, tx pgx.Tx, p Proposal) (Change, error) {
	id := idgen.New("chg")

	var (
		payloadCT    []byte
		payloadNonce []byte
		target       *int64
		secretID     *string
	)
	switch p.Op {
	case OpSet:
		if err := ValidateValue(p.Value); err != nil {
			return Change{}, err
		}
		nonce, ct, err := s.EncryptChangeValue(ctx, tx, p.Scope.OrgID, p.Scope.ProjectID, p.Scope.EnvID, p.Key, id, p.Value)
		if err != nil {
			return Change{}, err
		}
		payloadNonce, payloadCT = nonce, ct
	case OpDelete:
		// A tombstone proposal carries no payload: there is no value to seal.
	case OpRollback:
		if p.TargetVer <= 0 {
			return Change{}, ErrConflict
		}
		v := p.TargetVer
		target = &v
	default:
		return Change{}, ErrInvalidKey
	}

	// Record the secret id when the key already exists. It is advisory: approval resolves the row
	// by (env_id, key) under a lock, which is the row the allocator will touch either way.
	const findSecret = `SELECT id FROM secrets WHERE env_id = $1 AND key = $2`
	var sid string
	switch err := tx.QueryRow(ctx, findSecret, p.Scope.EnvID, p.Key).Scan(&sid); {
	case err == nil:
		secretID = &sid
	case errors.Is(err, pgx.ErrNoRows):
		secretID = nil
	default:
		return Change{}, err
	}

	ch := Change{
		ID:            id,
		OrgID:         p.Scope.OrgID,
		ProjectID:     p.Scope.ProjectID,
		EnvID:         p.Scope.EnvID,
		Key:           p.Key,
		Op:            p.Op,
		PayloadCT:     payloadCT,
		PayloadNonce:  payloadNonce,
		BaseVersion:   p.BaseVer,
		TargetVersion: target,
		Status:        StatusPending,
		ProposerID:    p.Proposer.ID,
	}
	if secretID != nil {
		ch.SecretID = *secretID
	}

	const ins = `
INSERT INTO change_requests
  (id, org_id, project_id, env_id, secret_id, key, op, payload_ct, payload_nonce,
   base_version, target_version, status, proposer_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING created_at`
	err := tx.QueryRow(ctx, ins,
		ch.ID, ch.OrgID, ch.ProjectID, ch.EnvID, secretID, ch.Key, string(ch.Op),
		ch.PayloadCT, ch.PayloadNonce, ch.BaseVersion, ch.TargetVersion, ch.Status, ch.ProposerID,
	).Scan(&ch.CreatedAt)
	if err != nil {
		return Change{}, err
	}
	return ch, nil
}

// GetChange returns a change request inside an organization. A change in another organization is
// ErrNotFound, exactly as if it did not exist.
func (s *Store) GetChange(ctx context.Context, orgID, id string) (Change, error) {
	return s.getChange(ctx, s.Pool(), orgID, id)
}

// GetChangeTx reads a change request inside the caller's transaction.
func (s *Store) GetChangeTx(ctx context.Context, tx pgx.Tx, orgID, id string) (Change, error) {
	return s.getChange(ctx, tx, orgID, id)
}

// changeColumns is the projection shared by every change_requests read, so a new column cannot be
// added to one query and forgotten in another.
const changeColumns = `
       c.id, c.org_id, c.project_id, c.env_id, COALESCE(c.secret_id, ''), c.key, c.op,
       c.payload_ct, c.payload_nonce, c.base_version, c.target_version, c.status, c.proposer_id,
       c.created_at, c.resolved_at, COALESCE(c.resolver_id, ''), p.slug, e.slug`

func (s *Store) getChange(ctx context.Context, q querier, orgID, id string) (Change, error) {
	const sql = `
SELECT ` + changeColumns + `
  FROM change_requests c
  JOIN projects p ON p.id = c.project_id
  JOIN environments e ON e.id = c.env_id
 WHERE c.id = $1 AND c.org_id = $2`
	return scanChange(q.QueryRow(ctx, sql, id, orgID))
}

// ListChanges returns the organization's change requests, newest first, optionally filtered by
// status. Visibility is filtered by the caller, because it depends on project grants.
func (s *Store) ListChanges(ctx context.Context, orgID, status string, limit int) ([]Change, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	const sql = `
SELECT ` + changeColumns + `
  FROM change_requests c
  JOIN projects p ON p.id = c.project_id
  JOIN environments e ON e.id = c.env_id
 WHERE c.org_id = $1 AND ($2 = '' OR c.status = $2)
 ORDER BY c.created_at DESC, c.id DESC
 LIMIT $3`
	rows, err := s.Pool().Query(ctx, sql, orgID, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Change, 0, 32)
	for rows.Next() {
		ch, err := scanChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// rowScanner is satisfied by pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanChange(r rowScanner) (Change, error) {
	var ch Change
	var op string
	var target *int64
	err := r.Scan(&ch.ID, &ch.OrgID, &ch.ProjectID, &ch.EnvID, &ch.SecretID, &ch.Key, &op,
		&ch.PayloadCT, &ch.PayloadNonce, &ch.BaseVersion, &target, &ch.Status, &ch.ProposerID,
		&ch.CreatedAt, &ch.ResolvedAt, &ch.ResolverID, &ch.ProjectSlug, &ch.EnvSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return Change{}, ErrNotFound
	}
	if err != nil {
		return Change{}, err
	}
	ch.Op = Op(op)
	ch.TargetVersion = target
	return ch, nil
}

// GrantsFor returns the caller's project grant levels in the organization.
func (s *Store) GrantsFor(ctx context.Context, orgID, userID string) (map[string]string, error) {
	const q = `
SELECT g.project_id, g.level
  FROM project_grants g
  JOIN projects p ON p.id = g.project_id
 WHERE p.org_id = $1 AND g.user_id = $2`
	rows, err := s.Pool().Query(ctx, q, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string, 8)
	for rows.Next() {
		var projectID, level string
		if err := rows.Scan(&projectID, &level); err != nil {
			return nil, err
		}
		out[projectID] = level
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// InTxWithCommit runs fn in a transaction and commits when fn returns commitOn, or when it returns
// nil. Every other error rolls back.
//
// It exists for exactly one case: marking a change request stale is a state change that must be
// committed *and* reported to the caller as a 409, and an error-returning transaction would roll
// the staleness back. Committing on a named sentinel makes that deliberate and narrow rather than
// turning every error into a commit.
func (s *Store) InTxWithCommit(ctx context.Context, commitOn error, fn func(pgx.Tx) error) error {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	err = fn(tx)
	if err != nil && (commitOn == nil || !errors.Is(err, commitOn)) {
		return err
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return cerr
	}
	committed = true
	return err
}

// ApproveTx applies a pending change request inside the caller's transaction.
//
// The order below is the specification's order (SPEC §2.9, docs/CONTRACTS.md §9) and it is the
// reason double approval is impossible:
//
//  1. Proposer == approver is a 403 before any state change, so a self-approval cannot even consume
//     the request.
//  2. The approver must be an owner or an admin.
//  3. The status moves pending -> approved with a conditional UPDATE. That statement is a
//     compare-and-swap: Postgres serialises the two concurrent approvers on the row, the first
//     commits, and the second re-evaluates its WHERE clause against the committed row, finds
//     status no longer 'pending', and affects zero rows. Zero rows is ErrAlreadyResolved (409).
//     There is no read-then-write window to lose, so the change cannot be applied twice and a
//     second resolver cannot overwrite the first resolver's decision.
//  4. Only then is the secret row locked FOR UPDATE, and the recorded base_version compared with
//     the live current_version. The lock is taken after the request is claimed, so a writer that
//     is applying its own change cannot deadlock against us in the opposite order: every approver
//     takes change_requests then secrets.
//  5. A mismatch marks the request stale, audits change.stale and returns ErrStale. Nothing is
//     applied and no version is allocated.
//  6. A match applies the change through the same allocator path as a direct write, in this
//     transaction.
func (s *Store) ApproveTx(ctx context.Context, tx pgx.Tx, ch Change, approver ActorRef, approverIsManager bool, w audit.Writer, ev audit.Event) (Applied, error) {
	// 1. Two-person rule.
	if ch.ProposerID == approver.ID {
		return Applied{}, ErrSelfApproval
	}
	// 2. Approver authority.
	if !approverIsManager {
		return Applied{}, ErrNotApprover
	}

	// 3. Claim the request. Zero rows means someone else resolved it first.
	const claim = `
UPDATE change_requests
   SET status = 'approved', resolved_at = now(), resolver_id = $2
 WHERE id = $1 AND org_id = $3 AND status = 'pending'
 RETURNING key, op, env_id, project_id, base_version, target_version`
	var (
		claimedKey, claimedOp, claimedEnv, claimedProject string
		claimedBase                                       int64
		claimedTarget                                     *int64
	)
	err := tx.QueryRow(ctx, claim, ch.ID, approver.ID, ch.OrgID).
		Scan(&claimedKey, &claimedOp, &claimedEnv, &claimedProject, &claimedBase, &claimedTarget)
	if errors.Is(err, pgx.ErrNoRows) {
		return Applied{}, ErrAlreadyResolved
	}
	if err != nil {
		return Applied{}, err
	}
	// Apply what the database says the request is, not what a caller passed in: the RETURNING row is
	// the authoritative one that was just claimed. That includes base_version and target_version, so
	// the staleness comparison below cannot be influenced by anything outside this row.
	ch.Key = claimedKey
	ch.Op = Op(claimedOp)
	ch.EnvID = claimedEnv
	ch.ProjectID = claimedProject
	ch.BaseVersion = claimedBase
	ch.TargetVersion = claimedTarget

	// 4. Lock the secret row and read the live version.
	//
	// A key that does not exist yet is the hard case: SELECT ... FOR UPDATE finds no row, takes no
	// lock, and a concurrent writer could then create the key between this read and the apply
	// below, letting the change be applied on top of a version the proposer never saw. For a set,
	// the row is therefore created (or found) *before* the lock, so the lock always exists:
	//
	//	INSERT ... ON CONFLICT (env_id, key) DO NOTHING   -- blocks a concurrent creator, then no-ops
	//	SELECT current_version ... FOR UPDATE             -- now this always locks a real row
	//
	// If another transaction created the key first, this transaction blocks on the insert until
	// that one commits, then reads the committed current_version, which no longer equals the
	// recorded base_version (0). The change is stale, which is the correct answer.
	if ch.Op == OpSet {
		const ensure = `
INSERT INTO secrets (id, env_id, key)
VALUES ($1, $2, $3)
ON CONFLICT (env_id, key) DO NOTHING`
		if _, err := tx.Exec(ctx, ensure, idgen.New("sec"), ch.EnvID, ch.Key); err != nil {
			return Applied{}, err
		}
	}

	const lock = `SELECT current_version FROM secrets WHERE env_id = $1 AND key = $2 FOR UPDATE`
	var current int64
	err = tx.QueryRow(ctx, lock, ch.EnvID, ch.Key).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		current = 0
	} else if err != nil {
		return Applied{}, err
	}

	// 5. Stale: the key moved under the proposer. Nothing is applied.
	//
	// A delete or a rollback whose key has since disappeared is stale too: version 0 is not a
	// state those operations can be applied to, and treating it as a match would resurrect a key
	// or roll back into nothing.
	if current != ch.BaseVersion || (ch.Op != OpSet && current == 0) {
		const mark = `UPDATE change_requests SET status = 'stale' WHERE id = $1`
		if _, err := tx.Exec(ctx, mark, ch.ID); err != nil {
			return Applied{}, err
		}
		if err := appendAudit(ctx, tx, w, ev, audit.ActionChangeStale, ChangeTarget(ch.ID), audit.ResultSuccess); err != nil {
			return Applied{}, err
		}
		return Applied{}, ErrStale
	}

	// 6. Apply through the allocator, in this transaction.
	sc := Scope{OrgID: ch.OrgID, ProjectID: ch.ProjectID, EnvID: ch.EnvID}
	wr := WriteRequest{
		Scope:         sc,
		Key:           ch.Key,
		Op:            ch.Op,
		Actor:         approver,
		TargetVersion: derefInt64(ch.TargetVersion),
	}
	if ch.Op == OpSet {
		value, err := s.DecryptChangeValue(ctx, tx, ch)
		if err != nil {
			return Applied{}, err
		}
		wr.Value = value
	}

	applied, err := s.ApplyTx(ctx, tx, wr)
	if err != nil {
		return Applied{}, err
	}

	// change.approved is written only once the change has actually been applied, so a request that
	// is approved and then found stale (or that fails to apply) never claims an approval that did
	// not happen. Both events are in this transaction, so they commit with the value.
	if err := appendAudit(ctx, tx, w, ev, audit.ActionChangeApproved, ChangeTarget(ch.ID), audit.ResultSuccess); err != nil {
		return Applied{}, err
	}
	if err := appendAudit(ctx, tx, w, ev, actionForOp(ch.Op), SecretTarget(ch.ProjectID, ch.EnvID, ch.Key), audit.ResultSuccess); err != nil {
		return Applied{}, err
	}
	return applied, nil
}

// RejectTx marks a pending request rejected. A request that is no longer pending is
// ErrAlreadyResolved (409), decided by the same conditional update that makes double approval
// impossible.
func (s *Store) RejectTx(ctx context.Context, tx pgx.Tx, ch Change, resolver ActorRef, w audit.Writer, ev audit.Event) error {
	const reject = `
UPDATE change_requests
   SET status = 'rejected', resolved_at = now(), resolver_id = $2
 WHERE id = $1 AND org_id = $3 AND status = 'pending'`
	tag, err := tx.Exec(ctx, reject, ch.ID, resolver.ID, ch.OrgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAlreadyResolved
	}
	return appendAudit(ctx, tx, w, ev, audit.ActionChangeRejected, ChangeTarget(ch.ID), audit.ResultSuccess)
}

// appendAudit writes one event inside the caller's transaction, so the audit row commits with the
// change it describes. A nil writer is a no-op rather than a panic.
func appendAudit(ctx context.Context, tx pgx.Tx, w audit.Writer, ev audit.Event, action, target string, result audit.Result) error {
	if w == nil {
		return nil
	}
	ev.Action = action
	ev.Target = target
	ev.Result = result
	_, err := w.AppendTx(ctx, tx, ev)
	return err
}

// actionForOp maps a mutation to its frozen audit action name.
func actionForOp(op Op) string {
	switch op {
	case OpDelete:
		return audit.ActionSecretDelete
	case OpRollback:
		return audit.ActionSecretRollback
	default:
		return audit.ActionSecretWrite
	}
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
