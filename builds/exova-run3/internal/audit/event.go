// Package audit is the audit-event model: the event shape, the action names, the
// canonical encoding and the hash (docs/CONTRACTS.md §3, §7).
//
// This file is a contract that every other slice compiles against. The chain
// itself — appending under the per-scope head lock, and verifying a stored chain —
// belongs to the audit slice and is deliberately not implemented here.
//
// The hash covers every field of the event except the hash itself, in a fixed
// order, with HTML escaping off and microsecond UTC timestamps, so that a row
// rebuilt from the database produces byte-identical canonical JSON. Anything that
// changes this encoding changes every hash ever written, which is why §7 requires a
// canon_version marker and a migration before a field is added.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ActorKind is the kind of principal an event is attributed to. The values match
// audit_events.actor_kind.
type ActorKind string

const (
	ActorUser      ActorKind = "user"
	ActorService   ActorKind = "service"
	ActorPlatform  ActorKind = "platform"
	ActorAnonymous ActorKind = "anonymous"
)

// Result is the outcome recorded on an event.
type Result string

const (
	ResultSuccess Result = "success"
	ResultDenied  Result = "denied"
	ResultFailed  Result = "failed"
)

// PlatformScope is the chain scope for the platform admin, for unauthenticated
// callers and for anonymous denials. Every other scope is an organization ID.
const PlatformScope = "platform"

// GenesisHash is the prev_hash of the first event in a scope: 32 zero bytes as
// hex. Verify recomputes each link from the row's own prev_hash column, so this
// value matters only to the writer that starts a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Action names (docs/CONTRACTS.md §3). No slice invents another one.
const (
	ActionLoginSuccess = "login.success"
	ActionLoginFailure = "login.failure"
	ActionLogout       = "logout"

	ActionSecretRead     = "secret.read"
	ActionSecretWrite    = "secret.write"
	ActionSecretDelete   = "secret.delete"
	ActionSecretRollback = "secret.rollback"

	ActionChangeCreated  = "change.created"
	ActionChangeApproved = "change.approved"
	ActionChangeRejected = "change.rejected"
	ActionChangeStale    = "change.stale"

	ActionMemberAdded       = "member.added"
	ActionMemberRemoved     = "member.removed"
	ActionMemberRoleChanged = "member.role_changed"

	ActionGrantSet     = "grant.set"
	ActionGrantRevoked = "grant.revoked"

	ActionTokenIssued  = "token.issued"
	ActionTokenRevoked = "token.revoked"

	ActionProjectCreated     = "project.created"
	ActionEnvironmentCreated = "environment.created"

	ActionOrganizationCreated  = "organization.created"
	ActionOrganizationDisabled = "organization.disabled"

	ActionDenied = "denied"

	ActionMasterKeyRotated = "masterkey.rotated"
)

// ActionNames lists every action name, for validation and for tests that assert no
// slice writes an invented one.
var ActionNames = []string{
	ActionLoginSuccess, ActionLoginFailure, ActionLogout,
	ActionSecretRead, ActionSecretWrite, ActionSecretDelete, ActionSecretRollback,
	ActionChangeCreated, ActionChangeApproved, ActionChangeRejected, ActionChangeStale,
	ActionMemberAdded, ActionMemberRemoved, ActionMemberRoleChanged,
	ActionGrantSet, ActionGrantRevoked,
	ActionTokenIssued, ActionTokenRevoked,
	ActionProjectCreated, ActionEnvironmentCreated,
	ActionOrganizationCreated, ActionOrganizationDisabled,
	ActionDenied,
	ActionMasterKeyRotated,
}

// IsKnownAction reports whether action is one of the frozen names.
func IsKnownAction(action string) bool {
	for _, a := range ActionNames {
		if a == action {
			return true
		}
	}
	return false
}

// Event is one audit record. The fields map one to one onto audit_events.
//
// Scope is the chain the event belongs to — an organization ID, or PlatformScope.
// It is explicit rather than derived from OrgID, so an org-scoped event can never
// silently land on the platform chain.
type Event struct {
	Scope     string
	Seq       int64     // assigned by the writer; zero on input
	Timestamp time.Time // UTC, microsecond precision on the wire
	ActorID   string
	ActorKind ActorKind
	OrgID     string
	Action    string
	Target    string
	SourceIP  string
	Result    Result
	PrevHash  string
}

// Writer appends events to the chain. It is the only way a slice writes audit
// state, and it is the only cross-slice dependency the audit slice exposes.
//
// Append uses its own transaction. AppendTx joins the caller's transaction, so a
// secret write and its audit event commit or roll back together. Both return the
// stored event with Seq and the chain hash filled in; a caller that does not need
// them ignores the result.
type Writer interface {
	Append(ctx context.Context, e Event) (Event, error)
	AppendTx(ctx context.Context, tx pgx.Tx, e Event) (Event, error)
}

// TimestampLayout is the canonical timestamp form: UTC, microsecond precision,
// matching timestamptz. time.RFC3339Nano is not usable because it trims trailing
// zeros, which would make the canonical bytes depend on the value.
const TimestampLayout = "2006-01-02T15:04:05.000000Z"

// FormatTimestamp renders t as the canonical timestamp. The value is truncated to
// microseconds in UTC, because that is the precision PostgreSQL stores, so the
// bytes hashed at write time match the bytes hashed from a row at verify time.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(TimestampLayout)
}

// canonicalEvent fixes the field order and JSON names of the canonical form. The
// order of these fields is the hash input; do not reorder or rename them.
type canonicalEvent struct {
	Scope     string `json:"scope"`
	Seq       int64  `json:"seq"`
	Timestamp string `json:"ts"`
	Actor     string `json:"actor"`
	ActorKind string `json:"actor_kind"`
	Org       string `json:"org"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	SourceIP  string `json:"source_ip"`
	Result    string `json:"result"`
	PrevHash  string `json:"prev_hash"`
}

// Canonical returns the canonical JSON bytes for e with the given previous hash.
// HTML escaping is off so that a target containing '<', '>' or '&' hashes to the
// bytes actually stored rather than to \u003c escapes.
func Canonical(e Event, prevHash string) []byte {
	c := canonicalEvent{
		Scope:     e.Scope,
		Seq:       e.Seq,
		Timestamp: FormatTimestamp(e.Timestamp),
		Actor:     e.ActorID,
		ActorKind: string(e.ActorKind),
		Org:       e.OrgID,
		Action:    e.Action,
		Target:    e.Target,
		SourceIP:  e.SourceIP,
		Result:    string(e.Result),
		PrevHash:  prevHash,
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	// The canonical struct is fixed-width strings and an int64, so encoding cannot
	// fail; if it somehow did, an empty canonical form would be a silent chain
	// corruption, so panic rather than return bytes that hash to something wrong.
	if err := enc.Encode(c); err != nil {
		panic("audit: canonical encode failed: " + err.Error())
	}
	out := buf.Bytes()
	// json.Encoder appends a newline; the canonical form does not include it.
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == '\r') {
		out = out[:len(out)-1]
	}
	return out
}

// Hash returns the lowercase hex SHA-256 of prevHash || canonical JSON of e. The
// previous hash contributes its ASCII bytes, which is what a stored chain has.
func Hash(e Event, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(Canonical(e, prevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// Hash returns the chain hash of this event, computed against its own PrevHash.
//
// It is a method rather than a stored field so the hash can never disagree with the
// event it describes: there is no second copy to forget to update. The stored row
// carries the value, and verify recomputes it from the row's columns; this accessor is
// for the writer returning what it just wrote.
func (e Event) Hash() string { return Hash(e, e.PrevHash) }

// NopWriter is a Writer that discards events. It exists so a server can start
// before the audit slice lands, and it is never the production writer.
func NopWriter() Writer { return nopWriter{} }

type nopWriter struct{}

func (nopWriter) Append(context.Context, Event) (Event, error) { return Event{}, nil }

func (nopWriter) AppendTx(context.Context, pgx.Tx, Event) (Event, error) { return Event{}, nil }
