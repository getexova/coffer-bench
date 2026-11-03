package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

// MaxValue is the largest secret value in bytes.
const MaxValue = 65536

// MaxLiveKeys caps the live (non-deleted) keys per environment. Writes that
// would make a new key live beyond it get 409. It bounds the size of a
// listing and an export (at most MaxLiveKeys*MaxValue bytes of values).
// Concurrent creations of different keys may overshoot it slightly.
const MaxLiveKeys = 10000

var errTooManyKeys = conflict("environment already holds the maximum of 10000 live secrets")

// liveKeysFull reports whether env already holds MaxLiveKeys live keys other
// than key.
func liveKeysFull(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, envID, key string) (bool, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM secrets WHERE env_id=$1 AND NOT deleted AND key<>$2 LIMIT $3) x`,
		envID, key, MaxLiveKeys).Scan(&n)
	return n >= MaxLiveKeys, err
}

func secretTarget(sc *scope, key string) string {
	return sc.projectSlug + "/" + sc.envSlug + "/" + key
}

// integrityError is an AEAD open failure of a stored ciphertext: tampered,
// swapped or corrupted data (SPEC §4 Bound ciphertext).
type integrityError struct {
	target  string
	version int
}

func (e *integrityError) Error() string {
	return "secret decryption failed for " + e.target + " v" + strconv.Itoa(e.version)
}

// integrityFailure audits a decryption failure as a failed value exit (or
// write) and answers 500. The event is appended on a context the client
// cannot cancel; callers must have released their transaction first.
func (s *Server) integrityFailure(w http.ResponseWriter, r *http.Request, p *Principal, action string, ie *integrityError, extra map[string]any) {
	d := map[string]any{"version": ie.version, "reason": "integrity"}
	for k, v := range extra {
		d[k] = v
	}
	ctx, cancel := detached(r)
	defer cancel()
	if err := s.appender.Append(ctx, s.event(r, p, action, ie.target, audit.Failed, d)); err != nil {
		s.log.Error("audit append failed", "request_id", info(r).id, "action", action, "error", err.Error())
	}
	s.internalError(w, r, ie)
}

type secretMetaJSON struct {
	Key       string `json:"key"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opMeta, false)
	if sc == nil {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT key, current_version, updated_at, updated_by FROM secrets
		WHERE env_id=$1 AND NOT deleted ORDER BY key COLLATE "C"`, sc.envID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := make([]secretMetaJSON, 0, 64)
	for rows.Next() {
		var m secretMetaJSON
		var t time.Time
		if err := rows.Scan(&m.Key, &m.Version, &t, &m.UpdatedBy); err != nil {
			s.internalError(w, r, err)
			return
		}
		m.UpdatedAt = ts(t)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type secretValueJSON struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
	Value   string `json:"value"`
}

// readValue decrypts, audits (committed) and returns a value.
func (s *Server) readValue(w http.ResponseWriter, r *http.Request, p *Principal, sc *scope, key string, version int, ct []byte) {
	dek, err := s.dek(sc)
	if err != nil {
		s.internalError(w, r, errors.New("data key unwrap failed"))
		return
	}
	pt, err := crypto.Open(dek, ct, crypto.SecretAAD(sc.orgID, sc.projectID, sc.envID, key, version))
	if err != nil {
		s.integrityFailure(w, r, p, "secret.read", &integrityError{target: secretTarget(sc, key), version: version}, nil)
		return
	}
	if err := s.appender.Append(r.Context(), s.event(r, p, "secret.read", secretTarget(sc, key), audit.Success,
		map[string]any{"version": version})); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, secretValueJSON{Key: key, Version: version, Value: string(pt)})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opRead, true)
	if sc == nil {
		return
	}
	key := r.PathValue("key")
	var version int
	var ct []byte
	err := s.pool.QueryRow(r.Context(), `SELECT s.current_version, v.ciphertext FROM secrets s
		JOIN secret_versions v ON v.env_id=s.env_id AND v.key=s.key AND v.version=s.current_version
		WHERE s.env_id=$1 AND s.key=$2 AND NOT s.deleted AND NOT v.deleted`, sc.envID, key).Scan(&version, &ct)
	if errors.Is(err, pgx.ErrNoRows) {
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.readValue(w, r, p, sc, key, version, ct)
}

type versionJSON struct {
	Version   int    `json:"version"`
	Deleted   bool   `json:"deleted"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opMeta, true)
	if sc == nil {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT version, deleted, created_at, created_by FROM secret_versions
		WHERE env_id=$1 AND key=$2 ORDER BY version`, sc.envID, r.PathValue("key"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	// Streamed row by row: a key's history is unbounded, the server's memory
	// use for it is not.
	started := false
	var buf []byte
	for rows.Next() {
		var v versionJSON
		var t time.Time
		if err := rows.Scan(&v.Version, &v.Deleted, &t, &v.CreatedBy); err != nil {
			rows.Close()
			s.exportAbort(w, r, started, err)
			return
		}
		v.CreatedAt = ts(t)
		b, err := marshalNoHTML(v)
		if err != nil {
			rows.Close()
			s.exportAbort(w, r, started, err)
			return
		}
		if !started {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			started = true
			buf = append(buf[:0], '[')
		} else {
			buf = append(buf, ',')
		}
		buf = append(buf, b...)
		if len(buf) >= 32<<10 {
			if _, err := w.Write(buf); err != nil {
				return
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		s.exportAbort(w, r, started, err)
		return
	}
	if !started {
		s.deny(w, r, p, errNotFound)
		return
	}
	buf = append(buf, "]\n"...)
	_, _ = w.Write(buf)
}

// parseVersion parses a non-negative decimal integer made only of digits.
// ok=false means "not an integer" (400). Integers that cannot exist (0 or
// beyond int32) return n=0, ok=true (404 after the lookup).
func parseVersion(s string) (n int, ok bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v > 1<<31-1 {
		return 0, true
	}
	return int(v), true
}

func marshalNoHTML(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opRead, true)
	if sc == nil {
		return
	}
	n, ok := parseVersion(r.PathValue("n"))
	if !ok {
		writeError(w, badRequest("version must be an integer"))
		return
	}
	key := r.PathValue("key")
	var deleted bool
	var ct []byte
	err := s.pool.QueryRow(r.Context(), `SELECT deleted, ciphertext FROM secret_versions WHERE env_id=$1 AND key=$2 AND version=$3`,
		sc.envID, key, n).Scan(&deleted, &ct)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (deleted || ct == nil)) {
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.readValue(w, r, p, sc, key, n, ct)
}

// ---------------------------------------------------------------- writes

type writeKind string

const (
	wSet      writeKind = "set"
	wDelete   writeKind = "delete"
	wRollback writeKind = "rollback"
)

var writeAction = map[writeKind]string{wSet: "secret.write", wDelete: "secret.delete", wRollback: "secret.rollback"}

type writeReq struct {
	kind     writeKind
	key      string
	value    []byte // set
	to       int    // rollback
	expected *int
}

// writeResult carries the outcome of a write transaction.
type writeResult struct {
	status int
	body   any
	err    *apiError
	deny   bool // err is a 404 that must be audited as authz.denied
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opWrite, true)
	if sc == nil {
		return
	}
	var body struct {
		Value           *json.RawMessage `json:"value"`
		ExpectedVersion *json.RawMessage `json:"expected_version"`
	}
	if e := decodeBody(r, &body); e != nil {
		writeError(w, e)
		return
	}
	if body.Value == nil {
		writeError(w, badRequest("value is required"))
		return
	}
	var value *string
	if err := json.Unmarshal(*body.Value, &value); err != nil || value == nil {
		writeError(w, badRequest("value must be a string"))
		return
	}
	if len(*value) > MaxValue {
		writeError(w, badRequest("value must be at most 65536 bytes"))
		return
	}
	if !utf8.ValidString(*value) {
		writeError(w, badRequest("value must be valid UTF-8"))
		return
	}
	expected, e := parseExpected(body.ExpectedVersion)
	if e != nil {
		writeError(w, e)
		return
	}
	s.write(w, r, p, sc, writeReq{kind: wSet, key: r.PathValue("key"), value: []byte(*value), expected: expected})
}

// parseExpected parses an optional JSON expected_version (integer ≥ 0).
func parseExpected(raw *json.RawMessage) (*int, *apiError) {
	if raw == nil {
		return nil, nil
	}
	if string(*raw) == "null" {
		return nil, nil
	}
	n, ok := parseJSONInt(*raw)
	if !ok || n < 0 || n > 1<<31-1 {
		return nil, badRequest("expected_version must be an integer >= 0")
	}
	v := int(n)
	return &v, nil
}

// parseJSONInt accepts a raw JSON number token that is a plain integer
// (optional '-', digits only: no strings, fractions or exponents).
func parseJSONInt(raw []byte) (int64, bool) {
	t := strings.TrimSpace(string(raw))
	digits := strings.TrimPrefix(t, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opWrite, true)
	if sc == nil {
		return
	}
	var expected *int
	if q := r.URL.Query(); q.Has("expected_version") {
		v := q.Get("expected_version")
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || strings.TrimLeft(v, "0123456789") != "" {
			writeError(w, badRequest("expected_version must be an integer >= 0"))
			return
		}
		expected = &n
	}
	s.write(w, r, p, sc, writeReq{kind: wDelete, key: r.PathValue("key"), expected: expected})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opWrite, true)
	if sc == nil {
		return
	}
	var body struct {
		To              *json.RawMessage `json:"to"`
		ExpectedVersion *json.RawMessage `json:"expected_version"`
	}
	if e := decodeBody(r, &body); e != nil {
		writeError(w, e)
		return
	}
	if body.To == nil {
		writeError(w, badRequest("to is required"))
		return
	}
	to, ok := parseJSONInt(*body.To)
	if !ok {
		writeError(w, badRequest("to must be an integer"))
		return
	}
	expected, e := parseExpected(body.ExpectedVersion)
	if e != nil {
		writeError(w, e)
		return
	}
	if to < 1 || to > 1<<31-1 {
		// Well-formed but cannot exist.
		s.deny(w, r, p, errNotFound)
		return
	}
	s.write(w, r, p, sc, writeReq{kind: wRollback, key: r.PathValue("key"), to: int(to), expected: expected})
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, p *Principal, sc *scope, req writeReq) {
	var res writeResult
	var err error
	if sc.protected {
		res, err = s.proposeChange(r, p, sc, req)
	} else {
		res, err = s.applyWrite(r, p, sc, req)
	}
	if err != nil {
		var ie *integrityError
		if errors.As(err, &ie) {
			s.integrityFailure(w, r, p, writeAction[req.kind], ie, writeIntegrityDetails(req))
			return
		}
		s.internalError(w, r, err)
		return
	}
	if res.err != nil {
		if res.deny {
			s.deny(w, r, p, res.err)
		} else {
			writeError(w, res.err)
		}
		return
	}
	writeJSON(w, res.status, res.body)
}

var errMismatch = conflict("expected_version does not match the current version")

// errStale marks a change request whose key changed since it was proposed.
var errStale = conflict("the key has changed since the change was proposed; the change is now stale")

// applyWrite performs an immediate write on an unprotected environment.
func (s *Server) applyWrite(r *http.Request, p *Principal, sc *scope, req writeReq) (writeResult, error) {
	ctx := r.Context()
	dek, err := s.dek(sc)
	if err != nil {
		return writeResult{}, errors.New("data key unwrap failed")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return writeResult{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Re-judge the writer under the org lock (SPEC §2.11): a grant revoked
	// or lowered, a removal or a token revocation that committed before this
	// point applies to this write.
	p, deny, err := relockWrite(ctx, tx, p, sc)
	if err != nil || deny != nil {
		return derefResult(deny), err
	}
	actor := p.ActorID()
	res, version, err := s.applyLocked(ctx, tx, sc, dek, req, actor, nil, nil)
	if err != nil || res.err != nil {
		return res, err
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, writeAction[req.kind], secretTarget(sc, req.key), audit.Success,
		writeDetails(req, version))); err != nil {
		return writeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return writeResult{}, err
	}
	return writeResult{status: http.StatusOK, body: map[string]int{"version": version}}, nil
}

func writeIntegrityDetails(req writeReq) map[string]any {
	if req.kind == wRollback {
		return map[string]any{"to": req.to}
	}
	return nil
}

func writeDetails(req writeReq, version int) map[string]any {
	d := map[string]any{"version": version}
	if req.kind == wRollback {
		d["to"] = req.to
	}
	return d
}

// headState is the locked head row of a key.
type headState struct {
	exists  bool
	version int
	deleted bool
}

// lockHead locks (creating if create) the head row of key.
func lockHead(ctx context.Context, tx pgx.Tx, envID, key, actor string, create bool) (headState, error) {
	if create {
		if _, err := tx.Exec(ctx, `INSERT INTO secrets (env_id, key, current_version, deleted, updated_at, updated_by)
			VALUES ($1, $2, 0, true, now(), $3) ON CONFLICT DO NOTHING`, envID, key, actor); err != nil {
			return headState{}, err
		}
	}
	var h headState
	err := tx.QueryRow(ctx, `SELECT current_version, deleted FROM secrets WHERE env_id=$1 AND key=$2 FOR UPDATE`, envID, key).Scan(&h.version, &h.deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return headState{}, nil
	}
	if err != nil {
		return headState{}, err
	}
	h.exists = h.version > 0
	return h, nil
}

// applyLocked locks the head and applies req as version head+1. author is
// recorded as the version's creator. If plaintext is non-nil it overrides
// req.value (approved changes). The caller commits.
func (s *Server) applyLocked(ctx context.Context, tx pgx.Tx, sc *scope, dek []byte, req writeReq, author string, plaintext []byte, base *int) (writeResult, int, error) {
	head, err := lockHead(ctx, tx, sc.envID, req.key, author, req.kind == wSet)
	if err != nil {
		return writeResult{}, 0, err
	}
	if base != nil && head.version != *base {
		return writeResult{err: errStale}, 0, nil
	}
	if req.expected != nil && *req.expected != head.version {
		return writeResult{err: errMismatch}, 0, nil
	}
	var value []byte
	switch req.kind {
	case wSet:
		value = req.value
		if plaintext != nil {
			value = plaintext
		}
	case wDelete:
		if !head.exists || head.deleted {
			return writeResult{err: errNotFound, deny: true}, 0, nil
		}
	case wRollback:
		if !head.exists {
			return writeResult{err: errNotFound, deny: true}, 0, nil
		}
		v, found, err := s.versionValue(ctx, tx, sc, dek, req.key, req.to)
		if err != nil {
			return writeResult{}, 0, err
		}
		if !found {
			return writeResult{err: errNotFound, deny: true}, 0, nil
		}
		value = v
	}
	if req.kind != wDelete && (!head.exists || head.deleted) {
		full, err := liveKeysFull(ctx, tx, sc.envID, req.key)
		if err != nil {
			return writeResult{}, 0, err
		}
		if full {
			return writeResult{err: errTooManyKeys}, 0, nil
		}
	}
	version := head.version + 1
	var ct []byte
	if req.kind != wDelete {
		ct, err = crypto.Seal(dek, value, crypto.SecretAAD(sc.orgID, sc.projectID, sc.envID, req.key, version))
		if err != nil {
			return writeResult{}, 0, err
		}
	}
	deleted := req.kind == wDelete
	b := &pgx.Batch{}
	b.Queue(`INSERT INTO secret_versions (env_id, key, version, deleted, ciphertext, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,now(),$6)`, sc.envID, req.key, version, deleted, ct, author)
	b.Queue(`UPDATE secrets SET current_version=$3, deleted=$4, updated_at=now(), updated_by=$5 WHERE env_id=$1 AND key=$2`,
		sc.envID, req.key, version, deleted, author)
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return writeResult{}, 0, err
	}
	return writeResult{}, version, nil
}

// versionValue decrypts version n of key; found=false for missing/tombstone.
func (s *Server) versionValue(ctx context.Context, tx pgx.Tx, sc *scope, dek []byte, key string, n int) ([]byte, bool, error) {
	var deleted bool
	var ct []byte
	err := tx.QueryRow(ctx, `SELECT deleted, ciphertext FROM secret_versions WHERE env_id=$1 AND key=$2 AND version=$3`,
		sc.envID, key, n).Scan(&deleted, &ct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if deleted || ct == nil {
		return nil, false, nil
	}
	pt, err := crypto.Open(dek, ct, crypto.SecretAAD(sc.orgID, sc.projectID, sc.envID, key, n))
	if err != nil {
		return nil, false, &integrityError{target: secretTarget(sc, key), version: n}
	}
	return pt, true, nil
}

// proposeChange creates a change request for a protected environment.
func (s *Server) proposeChange(r *http.Request, p *Principal, sc *scope, req writeReq) (writeResult, error) {
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return writeResult{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, deny, err := relockWrite(ctx, tx, p, sc)
	if err != nil || deny != nil {
		return derefResult(deny), err
	}
	var head headState
	err = tx.QueryRow(ctx, `SELECT current_version, deleted FROM secrets WHERE env_id=$1 AND key=$2`, sc.envID, req.key).Scan(&head.version, &head.deleted)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return writeResult{}, err
	}
	head.exists = err == nil && head.version > 0
	if !head.exists {
		head.version = 0
	}
	if req.expected != nil && *req.expected != head.version {
		return writeResult{err: errMismatch}, nil
	}
	if req.kind == wSet && (!head.exists || head.deleted) {
		// Checked again when the change is applied.
		full, err := liveKeysFull(ctx, tx, sc.envID, req.key)
		if err != nil {
			return writeResult{}, err
		}
		if full {
			return writeResult{err: errTooManyKeys}, nil
		}
	}
	id := crypto.NewID("chg")
	var ct []byte
	var rollbackTo *int
	switch req.kind {
	case wSet:
		dek, err := s.dek(sc)
		if err != nil {
			return writeResult{}, errors.New("data key unwrap failed")
		}
		ct, err = crypto.Seal(dek, req.value, crypto.ChangeAAD(sc.orgID, sc.projectID, sc.envID, req.key, id))
		if err != nil {
			return writeResult{}, err
		}
	case wDelete:
		if !head.exists || head.deleted {
			return writeResult{err: errNotFound, deny: true}, nil
		}
	case wRollback:
		if !head.exists {
			return writeResult{err: errNotFound, deny: true}, nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM secret_versions WHERE env_id=$1 AND key=$2 AND version=$3 AND NOT deleted)`,
			sc.envID, req.key, req.to).Scan(&exists); err != nil {
			return writeResult{}, err
		}
		if !exists {
			return writeResult{err: errNotFound, deny: true}, nil
		}
		to := req.to
		rollbackTo = &to
	}
	var human *string
	if h := p.humanID(); h != "" {
		human = &h
	}
	if _, err := tx.Exec(ctx, `INSERT INTO change_requests (id, org_id, project_id, env_id, key, op, ciphertext, rollback_to,
		expected_version, base_version, status, proposed_by, proposed_by_user)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11,$12)`,
		id, sc.orgID, sc.projectID, sc.envID, req.key, string(req.kind), ct, rollbackTo, req.expected, head.version,
		p.ActorID(), human); err != nil {
		return writeResult{}, err
	}
	details := map[string]any{"change_id": id, "op": string(req.kind), "base_version": head.version}
	if rollbackTo != nil {
		details["to"] = *rollbackTo
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "change.create", secretTarget(sc, req.key), audit.Success, details)); err != nil {
		return writeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return writeResult{}, err
	}
	return writeResult{status: http.StatusAccepted, body: map[string]string{"status": "pending", "change_id": id}}, nil
}

// ---------------------------------------------------------------- export

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveSecretScope(w, r, p, opRead, false)
	if sc == nil {
		return
	}
	format := "json"
	if q := r.URL.Query(); q.Has("format") {
		format = q.Get("format")
	}
	if format != "json" && format != "dotenv" {
		writeError(w, badRequest("format must be dotenv or json"))
		return
	}
	ctx := r.Context()
	// The key list is a snapshot; values are then fetched, decrypted, audited
	// and written in batches, so memory stays bounded by one batch no matter
	// how large the environment is. Version rows are immutable, so the
	// export is consistent as of the snapshot.
	type kv struct {
		key     string
		version int
	}
	rows, err := s.pool.Query(ctx, `SELECT s.key, s.current_version FROM secrets s
		JOIN secret_versions v ON v.env_id=s.env_id AND v.key=s.key AND v.version=s.current_version
		WHERE s.env_id=$1 AND NOT s.deleted AND NOT v.deleted ORDER BY s.key COLLATE "C"`, sc.envID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (kv, error) {
		var it kv
		err := row.Scan(&it.key, &it.version)
		return it, err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var dek []byte
	if len(items) > 0 {
		if dek, err = s.dek(sc); err != nil {
			s.internalError(w, r, errors.New("data key unwrap failed"))
			return
		}
	}
	started := false
	var buf []byte
	for i, first := 0, true; i < len(items); first = false {
		n := min(exportBatch, len(items)-i)
		batch := items[i : i+n]
		i += n
		keys := make([]string, n)
		versions := make([]int32, n)
		for j, it := range batch {
			keys[j], versions[j] = it.key, int32(it.version)
		}
		cts := make(map[string][]byte, n)
		crow, err := s.pool.Query(ctx, `SELECT v.key, v.ciphertext FROM secret_versions v
			JOIN unnest($2::text[], $3::int[]) AS b(key, version) ON b.key=v.key AND b.version=v.version
			WHERE v.env_id=$1`, sc.envID, keys, versions)
		if err == nil {
			for crow.Next() {
				var k string
				var ct []byte
				if err = crow.Scan(&k, &ct); err != nil {
					break
				}
				cts[k] = ct
			}
			crow.Close()
			if err == nil {
				err = crow.Err()
			}
		}
		if err != nil {
			s.exportAbort(w, r, started, err)
			return
		}
		values := make([][]byte, n)
		events := make([]*audit.Event, 0, n)
		for j, it := range batch {
			pt, err := crypto.Open(dek, cts[it.key], crypto.SecretAAD(sc.orgID, sc.projectID, sc.envID, it.key, it.version))
			if err != nil {
				ie := &integrityError{target: secretTarget(sc, it.key), version: it.version}
				if !started {
					s.integrityFailure(w, r, p, "secret.read", ie, map[string]any{"via": "export"})
					return
				}
				s.auditDetached(r, s.event(r, p, "secret.read", ie.target, audit.Failed,
					map[string]any{"version": ie.version, "reason": "integrity", "via": "export"}))
				s.exportAbort(w, r, started, ie)
				return
			}
			values[j] = pt
			events = append(events, s.event(r, p, "secret.read", secretTarget(sc, it.key), audit.Success,
				map[string]any{"version": it.version, "via": "export"}))
		}
		// Audited (committed) before any of the batch's values leave.
		if err := s.appender.Append(ctx, events...); err != nil {
			s.exportAbort(w, r, started, err)
			return
		}
		if !started {
			if format == "dotenv" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			} else {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(http.StatusOK)
			started = true
		}
		buf = buf[:0]
		for j, it := range batch {
			if format == "dotenv" {
				buf = append(buf, it.key...)
				buf = append(buf, `="`...)
				buf = append(buf, DotenvEscape(string(values[j]))...)
				buf = append(buf, "\"\n"...)
				continue
			}
			if first && j == 0 {
				buf = append(buf, '{')
			} else {
				buf = append(buf, ',')
			}
			k, _ := marshalNoHTML(it.key)
			v, _ := marshalNoHTML(string(values[j]))
			buf = append(buf, k...)
			buf = append(buf, ':')
			buf = append(buf, v...)
		}
		if _, err := w.Write(buf); err != nil {
			return // client gone; every value sent was audited
		}
	}
	if format == "dotenv" {
		if !started {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
		}
		return
	}
	if !started {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}\n"))
		return
	}
	_, _ = w.Write([]byte("}\n"))
}

// exportBatch is how many values an export decrypts and holds at once.
const exportBatch = 256

// exportAbort ends a failed export: a JSON 500 if nothing was sent yet,
// otherwise the connection is aborted so the client sees a truncated
// response rather than a complete-looking partial export.
func (s *Server) exportAbort(w http.ResponseWriter, r *http.Request, started bool, err error) {
	if !started {
		s.internalError(w, r, err)
		return
	}
	s.log.Error("export aborted", "request_id", info(r).id, "route", info(r).route, "error", err.Error())
	panic(http.ErrAbortHandler)
}

// auditDetached appends an event on a context the client cannot cancel.
func (s *Server) auditDetached(r *http.Request, e *audit.Event) {
	ctx, cancel := detached(r)
	defer cancel()
	if err := s.appender.Append(ctx, e); err != nil {
		s.log.Error("audit append failed", "request_id", info(r).id, "action", e.Action, "error", err.Error())
	}
}

// DotenvEscape escapes a value for KEY="VALUE" (SPEC §7.1).
func DotenvEscape(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '$':
			b.WriteString(`\$`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
