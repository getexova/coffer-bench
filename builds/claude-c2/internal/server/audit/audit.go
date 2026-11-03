// Package audit implements Coffer's append-only, hash-chained audit log
// (CONTRACT §5.4).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PlatformChain is the chain name for platform-level events.
const PlatformChain = "platform"

// GenesisHash is the prev_hash of the first event in a chain.
var GenesisHash = strings.Repeat("0", 64)

// Results.
const (
	Success = "success"
	Denied  = "denied"
	Failed  = "failed"
)

// TSFormat is RFC 3339 UTC with exactly six fractional digits.
const TSFormat = "2006-01-02T15:04:05.000000Z"

// Event is one audit record.
type Event struct {
	Chain     string
	Seq       int64
	TS        time.Time
	OrgID     string // "" => null
	ActorType string
	ActorID   string
	Action    string
	Target    string
	SourceIP  string
	Result    string
	Details   map[string]any
	PrevHash  string
	Hash      string
}

// Querier is the subset of pgx.Tx / pgxpool.Pool used here.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}

const maxField = 2048

// Sanitize makes s storable and hashable deterministically: invalid UTF-8 is
// replaced, NUL removed (Postgres text/jsonb cannot hold it), and the length
// is capped on a rune boundary.
func Sanitize(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if len(s) > maxField {
		cut := maxField
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// normalizeDetails converts details into the canonical value space: strings
// (sanitized), int64, bool, nested maps. Anything else is stringified.
func normalizeDetails(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[Sanitize(k)] = normalizeValue(v)
	}
	return out
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return Sanitize(x)
	case bool:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case json.Number:
		return x
	case map[string]any:
		return normalizeDetails(x)
	default:
		return Sanitize(fmt.Sprint(x))
	}
}

// Canonical returns the canonical JSON of e without its hash.
func Canonical(e *Event) ([]byte, error) {
	var org any
	if e.OrgID != "" {
		org = e.OrgID
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	m := map[string]any{
		"action":     e.Action,
		"actor_id":   e.ActorID,
		"actor_type": e.ActorType,
		"chain":      e.Chain,
		"details":    details,
		"org_id":     org,
		"prev_hash":  e.PrevHash,
		"result":     e.Result,
		"seq":        e.Seq,
		"source_ip":  e.SourceIP,
		"target":     e.Target,
		"ts":         e.TS.UTC().Format(TSFormat),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// ComputeHash returns hex(sha256(prev_hash || canonical(e))).
func ComputeHash(e *Event) (string, error) {
	c, err := Canonical(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// prepare normalizes the fields of e that are stored.
func prepare(e *Event, now time.Time) {
	e.Chain = Sanitize(e.Chain)
	e.ActorType = Sanitize(e.ActorType)
	e.ActorID = Sanitize(e.ActorID)
	e.Action = Sanitize(e.Action)
	e.Target = Sanitize(e.Target)
	e.SourceIP = Sanitize(e.SourceIP)
	e.OrgID = Sanitize(e.OrgID)
	if e.Result == "" {
		e.Result = Success
	}
	e.Details = normalizeDetails(e.Details)
	e.TS = now.UTC().Truncate(time.Microsecond)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AppendTx appends events (all on the same chain, in order) inside the
// caller's transaction. The chain head row is locked until the caller's
// transaction ends, so the caller must keep the transaction short and must
// take any other row locks before calling this.
func AppendTx(ctx context.Context, tx Querier, events ...*Event) error {
	if len(events) == 0 {
		return nil
	}
	chain := events[0].Chain
	for _, e := range events {
		if e.Chain != chain {
			return errors.New("audit: AppendTx events must share a chain")
		}
	}
	var lastSeq int64
	var lastHash string
	err := tx.QueryRow(ctx, `SELECT last_seq, last_hash FROM audit_chains WHERE chain=$1 FOR UPDATE`, chain).Scan(&lastSeq, &lastHash)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_chains (chain, last_seq, last_hash) VALUES ($1, 0, $2) ON CONFLICT DO NOTHING`, chain, GenesisHash); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT last_seq, last_hash FROM audit_chains WHERE chain=$1 FOR UPDATE`, chain).Scan(&lastSeq, &lastHash)
	}
	if err != nil {
		return err
	}
	// The timestamp is taken after the chain lock so ts is monotonic per chain.
	now := time.Now()
	b := &pgx.Batch{}
	for _, e := range events {
		prepare(e, now)
		e.Seq = lastSeq + 1
		e.PrevHash = lastHash
		h, err := ComputeHash(e)
		if err != nil {
			return err
		}
		e.Hash = h
		details, err := json.Marshal(e.Details)
		if err != nil {
			return err
		}
		b.Queue(`INSERT INTO audit_events (chain, seq, ts, org_id, actor_type, actor_id, action, target, source_ip, result, details, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			e.Chain, e.Seq, e.TS, nullable(e.OrgID), e.ActorType, e.ActorID, e.Action, e.Target, e.SourceIP, e.Result, string(details), e.PrevHash, e.Hash)
		lastSeq, lastHash = e.Seq, e.Hash
	}
	b.Queue(`UPDATE audit_chains SET last_seq=$2, last_hash=$3 WHERE chain=$1`, chain, lastSeq, lastHash)
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	return br.Close()
}

// ListFilter filters List.
type ListFilter struct {
	Actor  string
	Action string
	Since  *time.Time
	Limit  int
}

// List returns events of chain, newest first.
func List(ctx context.Context, q Querier, chain string, f ListFilter) ([]Event, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	sql := `SELECT chain, seq, ts, COALESCE(org_id,''), COALESCE(actor_type,''), COALESCE(actor_id,''), COALESCE(action,''),
		COALESCE(target,''), COALESCE(source_ip,''), COALESCE(result,''), details, prev_hash, hash
		FROM audit_events WHERE chain=$1`
	args := []any{chain}
	if f.Actor != "" {
		args = append(args, f.Actor)
		sql += fmt.Sprintf(" AND actor_id=$%d", len(args))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		sql += fmt.Sprintf(" AND action=$%d", len(args))
	}
	if f.Since != nil {
		args = append(args, *f.Since)
		sql += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	args = append(args, f.Limit)
	sql += fmt.Sprintf(" ORDER BY seq DESC LIMIT $%d", len(args))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func scanEvent(rows pgx.Rows) (*Event, error) {
	var e Event
	var details []byte
	if err := rows.Scan(&e.Chain, &e.Seq, &e.TS, &e.OrgID, &e.ActorType, &e.ActorID, &e.Action, &e.Target,
		&e.SourceIP, &e.Result, &details, &e.PrevHash, &e.Hash); err != nil {
		return nil, err
	}
	e.TS = e.TS.UTC()
	d, err := decodeDetails(details)
	if err != nil {
		// Unparseable details are kept raw so verification flags the row.
		d = map[string]any{"_raw": string(details)}
	}
	e.Details = d
	return &e, nil
}

func decodeDetails(b []byte) (map[string]any, error) {
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// VerifyResult is the outcome of Verify.
type VerifyResult struct {
	Valid           bool   `json:"valid"`
	FirstInvalidSeq *int64 `json:"first_invalid_seq"`
}

// Verify recomputes chain and returns the first invalid sequence number.
func Verify(ctx context.Context, begin func(ctx context.Context) (pgx.Tx, error), chain string) (VerifyResult, error) {
	tx, err := begin(ctx)
	if err != nil {
		return VerifyResult{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	invalid := func(seq int64) (VerifyResult, error) { return VerifyResult{Valid: false, FirstInvalidSeq: &seq}, nil }

	prevSeq := int64(0)
	prevHash := GenesisHash
	const page = 2000
	for {
		rows, err := tx.Query(ctx, `SELECT chain, seq, ts, COALESCE(org_id,''), COALESCE(actor_type,''), COALESCE(actor_id,''), COALESCE(action,''),
			COALESCE(target,''), COALESCE(source_ip,''), COALESCE(result,''), details, prev_hash, hash
			FROM audit_events WHERE chain=$1 AND seq > $2 ORDER BY seq LIMIT $3`, chain, prevSeq, page)
		if err != nil {
			return VerifyResult{}, err
		}
		n := 0
		var bad *int64
		for rows.Next() {
			n++
			e, err := scanEvent(rows)
			if err != nil {
				rows.Close()
				return VerifyResult{}, err
			}
			expect := prevSeq + 1
			if e.Seq != expect {
				bad = &expect
				break
			}
			if e.PrevHash != prevHash {
				bad = &e.Seq
				break
			}
			h, err := ComputeHash(e)
			if err != nil || h != e.Hash {
				bad = &e.Seq
				break
			}
			prevSeq, prevHash = e.Seq, e.Hash
		}
		rows.Close()
		if err := rows.Err(); err != nil && bad == nil {
			return VerifyResult{}, err
		}
		if bad != nil {
			return invalid(*bad)
		}
		if n < page {
			break
		}
	}
	var headSeq int64
	var headHash string
	err = tx.QueryRow(ctx, `SELECT last_seq, last_hash FROM audit_chains WHERE chain=$1`, chain).Scan(&headSeq, &headHash)
	if errors.Is(err, pgx.ErrNoRows) {
		if prevSeq == 0 {
			return VerifyResult{Valid: true}, nil
		}
		return invalid(prevSeq + 1)
	}
	if err != nil {
		return VerifyResult{}, err
	}
	if headSeq != prevSeq || headHash != prevHash {
		return invalid(prevSeq + 1)
	}
	return VerifyResult{Valid: true}, nil
}
