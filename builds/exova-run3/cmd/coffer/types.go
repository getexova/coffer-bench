package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// flexTime parses the timestamp shapes a server may send (RFC 3339 with any
// fractional precision, or the audit log's microsecond form). An unparseable
// value is tolerated and rendered as "-" rather than failing the whole command:
// a display detail must not turn a successful request into an error.
type flexTime struct {
	t   time.Time
	set bool
}

func (f *flexTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000000Z",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			f.t = t
			f.set = true
			return nil
		}
	}
	return nil
}

func (f flexTime) time() time.Time {
	if !f.set {
		return time.Time{}
	}
	return f.t
}

func (f flexTime) String() string {
	if !f.set {
		return "-"
	}
	return formatTime(f.t)
}

// flexInt64 accepts both a JSON number and a numeric string.
type flexInt64 struct {
	v   int64
	set bool
}

func (f *flexInt64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	f.v = n
	f.set = true
	return nil
}

func (f flexInt64) String() string {
	if !f.set {
		return "-"
	}
	return strconv.FormatInt(f.v, 10)
}

// orgRef is the organization attached to a user.
type orgRef struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// userRef is the user attached to a login or /me response.
type userRef struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	Role               string  `json:"role"`
	MustChangePassword bool    `json:"must_change_password"`
	Organization       *orgRef `json:"organization"`
}

// tokenRef is the service-token scope reported by /me for a service token.
type tokenRef struct {
	ID        string   `json:"id"`
	Project   string   `json:"project"`
	Env       string   `json:"env"`
	Access    string   `json:"access"`
	ExpiresAt flexTime `json:"expires_at"`
}

// meResponse is GET /me.
type meResponse struct {
	Role         string    `json:"role"`
	Organization *orgRef   `json:"organization"`
	User         *userRef  `json:"user"`
	Token        *tokenRef `json:"token"`
}

// loginResponse is POST /auth/token.
type loginResponse struct {
	Token string   `json:"token"`
	User  *userRef `json:"user"`
}

// orgRow is one organization in the platform admin list.
type orgRow struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	CreatedAt  flexTime `json:"created_at"`
	DisabledAt flexTime `json:"disabled_at"`
}

// memberRow is one member of an organization.
type memberRow struct {
	ID                 string   `json:"id"`
	Email              string   `json:"email"`
	Role               string   `json:"role"`
	MustChangePassword bool     `json:"must_change_password"`
	CreatedAt          flexTime `json:"created_at"`
}

// grantRow is one project grant.
type grantRow struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Project string `json:"project"`
	Level   string `json:"level"`
}

// projectRow is one project.
type projectRow struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	CreatedAt flexTime `json:"created_at"`
}

// envRow is one environment.
type envRow struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	Protected bool     `json:"protected"`
	CreatedAt flexTime `json:"created_at"`
}

// secretRow is one entry of the secrets listing: metadata only, never a value.
type secretRow struct {
	Key       string    `json:"key"`
	Version   flexInt64 `json:"version"`
	UpdatedAt flexTime  `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// secretValue is a single-key read.
type secretValue struct {
	Key     string    `json:"key"`
	Version flexInt64 `json:"version"`
	Value   string    `json:"value"`
}

// versionRow is one entry of a key's history.
type versionRow struct {
	Version   flexInt64 `json:"version"`
	Deleted   bool      `json:"deleted"`
	CreatedAt flexTime  `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// changeRow is one change request.
type changeRow struct {
	ID            string    `json:"id"`
	Key           string    `json:"key"`
	Op            string    `json:"op"`
	Status        string    `json:"status"`
	Project       string    `json:"project"`
	Env           string    `json:"env"`
	BaseVersion   flexInt64 `json:"base_version"`
	TargetVersion flexInt64 `json:"target_version"`
	ProposerID    string    `json:"proposer_id"`
	Proposer      string    `json:"proposer"`
	CreatedAt     flexTime  `json:"created_at"`
	ResolvedAt    flexTime  `json:"resolved_at"`
}

// tokenRow is one service token. The token itself is never listed: the server
// shows it once, at creation.
type tokenRow struct {
	ID        string   `json:"id"`
	Project   string   `json:"project"`
	Env       string   `json:"env"`
	Access    string   `json:"access"`
	Name      string   `json:"name"`
	CreatedAt flexTime `json:"created_at"`
	ExpiresAt flexTime `json:"expires_at"`
	RevokedAt flexTime `json:"revoked_at"`
}

// tokenCreated is POST /tokens: the only response that carries the token.
type tokenCreated struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// auditRow is one audit event, per the field set E3 emits: seq, timestamp,
// actor, action, target, source_ip, result, prev_hash, hash. The extra fields are
// tolerated fallbacks so a shape variation cannot blank the table.
type auditRow struct {
	Seq       flexInt64 `json:"seq"`
	Timestamp flexTime  `json:"timestamp"`
	TS        flexTime  `json:"ts"`
	Actor     string    `json:"actor"`
	ActorID   string    `json:"actor_id"`
	ActorKind string    `json:"actor_kind"`
	Org       string    `json:"org"`
	OrgID     string    `json:"org_id"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	SourceIP  string    `json:"source_ip"`
	Result    string    `json:"result"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// when renders whichever timestamp field the server populated.
func (r auditRow) when() flexTime {
	if r.Timestamp.set {
		return r.Timestamp
	}
	return r.TS
}

// actor renders whichever actor field the server populated.
func (r auditRow) actor() string { return firstNonEmpty(r.Actor, r.ActorID, r.ActorKind) }

// verifyResult is GET /audit/verify and GET /admin/audit/verify.
//
// first_invalid_seq is a JSON number when the chain is broken and JSON null when
// it is intact, so it is a pointer: a null decoded into an int64 would read as 0
// and be reported as "invalid at sequence 0".
type verifyResult struct {
	Valid           bool   `json:"valid"`
	FirstInvalidSeq *int64 `json:"first_invalid_seq"`
}

// invalidSeq renders the first invalid sequence, or "-" when the chain is intact.
func (v verifyResult) invalidSeq() string {
	if v.FirstInvalidSeq == nil {
		return "-"
	}
	return strconv.FormatInt(*v.FirstInvalidSeq, 10)
}

// writeResult covers a secret write: 200 carries a version, 202 a change id.
type writeResult struct {
	Status   string    `json:"status"`
	ChangeID string    `json:"change_id"`
	Version  flexInt64 `json:"version"`
	Key      string    `json:"key"`
}

// decodeList decodes either {"<key>":[...]} or a bare [...] into out, so the
// CLI does not break on the wrapper the server chose.
func decodeList[T any](body []byte, key string, out *[]T) error {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err == nil {
		for _, candidate := range append([]string{key}, "items", "data", "results") {
			if raw, ok := wrapper[candidate]; ok {
				return json.Unmarshal(raw, out)
			}
		}
	}
	return json.Unmarshal(body, out)
}

// decodeObject decodes either {"<key>":{...}} or a bare {...} into out.
func decodeObject[T any](body []byte, key string, out *T) error {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err == nil {
		if raw, ok := wrapper[key]; ok {
			return json.Unmarshal(raw, out)
		}
	}
	return json.Unmarshal(body, out)
}
