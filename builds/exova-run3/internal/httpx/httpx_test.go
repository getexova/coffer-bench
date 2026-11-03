package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// envelope is the only error shape the API may emit.
type envelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeEnvelope(t *testing.T, body []byte) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v\nbody: %s", err, body)
	}
	return env
}

func TestStatusFor(t *testing.T) {
	tests := map[string]int{
		CodeValidation:      http.StatusBadRequest,
		CodeUnauthenticated: http.StatusUnauthorized,
		CodeForbidden:       http.StatusForbidden,
		CodeNotFound:        http.StatusNotFound,
		CodeConflict:        http.StatusConflict,
		CodeBodyTooLarge:    http.StatusRequestEntityTooLarge,
		CodeRateLimited:     http.StatusTooManyRequests,
		CodeInternal:        http.StatusInternalServerError,
	}
	for code, want := range tests {
		if got := StatusFor(code); got != want {
			t.Errorf("StatusFor(%q) = %d, want %d", code, got, want)
		}
	}
	// An invented code must never map to a success status.
	if got := StatusFor("made_up_code"); got != http.StatusInternalServerError {
		t.Errorf("StatusFor(unknown) = %d, want 500", got)
	}
}

func TestWriteJSONSetsSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]string{"status": "ok"})

	resp := rec.Result()
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORS header present: %q", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWriteTextKeepsSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteText(rec, http.StatusOK, "text/plain; charset=utf-8", []byte("KEY=\"value\"\n"))

	resp := rec.Result()
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{"validation", Validation("bad key format"), http.StatusBadRequest, CodeValidation, "bad key format"},
		{"unauthenticated", Unauthenticated("authentication required"), http.StatusUnauthorized, CodeUnauthenticated, "authentication required"},
		{"forbidden", Forbidden("not permitted"), http.StatusForbidden, CodeForbidden, "not permitted"},
		{"not found", NotFound("not found"), http.StatusNotFound, CodeNotFound, "not found"},
		{"conflict", Conflict("version mismatch"), http.StatusConflict, CodeConflict, "version mismatch"},
		{"too large", TooLarge("too big"), http.StatusRequestEntityTooLarge, CodeBodyTooLarge, "too big"},
		{"rate limited", RateLimited("slow down"), http.StatusTooManyRequests, CodeRateLimited, "slow down"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
			WriteError(rec, req, tt.err)

			if rec.Code != tt.status {
				t.Errorf("status = %d, want %d", rec.Code, tt.status)
			}
			env := decodeEnvelope(t, rec.Body.Bytes())
			if env.Error.Code != tt.code {
				t.Errorf("code = %q, want %q", env.Error.Code, tt.code)
			}
			if env.Error.Message != tt.message {
				t.Errorf("message = %q, want %q", env.Error.Message, tt.message)
			}
		})
	}
}

func TestWriteErrorUnknownErrorIsInternal(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	// A raw database error must never reach the client.
	WriteError(rec, req, errors.New(`pq: relation "secrets" does not exist at /home/coffer/ws/internal/store`))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	env := decodeEnvelope(t, rec.Body.Bytes())
	if env.Error.Code != CodeInternal {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeInternal)
	}
	if env.Error.Message != InternalMessage {
		t.Errorf("message = %q, want the literal %q", env.Error.Message, InternalMessage)
	}
	body := rec.Body.String()
	for _, leak := range []string{"secrets", "relation", "/home/coffer", "pq:"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks %q: %s", leak, body)
		}
	}
}

func TestWriteErrorInternalWrapsCause(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	WriteError(rec, req, Internal(errors.New("connection refused to db.internal:5432")))

	env := decodeEnvelope(t, rec.Body.Bytes())
	if env.Error.Message != InternalMessage {
		t.Errorf("message = %q, want %q", env.Error.Message, InternalMessage)
	}
	if strings.Contains(rec.Body.String(), "db.internal") {
		t.Error("body leaks the database host")
	}
}

func TestWriteErrorInventedCodeBecomesInternal(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	WriteError(rec, req, &Error{Code: "totally_made_up", Message: "should not be echoed"})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	env := decodeEnvelope(t, rec.Body.Bytes())
	if env.Error.Code != CodeInternal {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeInternal)
	}
	if strings.Contains(rec.Body.String(), "totally_made_up") {
		t.Error("body echoes an invented code")
	}
}

func TestWriteErrorNilIsInternal(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	WriteError(rec, req, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestWithMessage(t *testing.T) {
	base := NotFound("not found")
	specific := WithMessage(base, "no such project")
	if specific.Message != "no such project" {
		t.Errorf("Message = %q", specific.Message)
	}
	if base.Message != "not found" {
		t.Error("WithMessage mutated the original error")
	}
	if specific.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", specific.Code, CodeNotFound)
	}
}

func TestDecodeJSONValid(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(`{"value":"hello"}`))

	var dst payload
	if !DecodeJSON(rec, req, &dst) {
		t.Fatalf("DecodeJSON failed: %s", rec.Body)
	}
	if dst.Value != "hello" {
		t.Errorf("Value = %q, want hello", dst.Value)
	}
}

func TestDecodeJSONMalformed(t *testing.T) {
	for _, body := range []string{
		`{"value":`,
		`not json`,
		``,
		`{"value":"a"} {"value":"b"}`,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(body))

		var dst map[string]any
		if DecodeJSON(rec, req, &dst) {
			t.Errorf("DecodeJSON accepted %q", body)
			continue
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status for %q = %d, want 400", body, rec.Code)
		}
		env := decodeEnvelope(t, rec.Body.Bytes())
		if env.Error.Code != CodeValidation {
			t.Errorf("code for %q = %q, want %q", body, env.Error.Code, CodeValidation)
		}
	}
}

func TestDecodeJSONUnknownFieldIsRejected(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}

	rec := httptest.NewRecorder()
	// A field the caller may not set must be a 400, never a silent no-op.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(`{"value":"a","role":"owner"}`))

	var dst payload
	if DecodeJSON(rec, req, &dst) {
		t.Fatal("DecodeJSON accepted an unknown field")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestDecodeJSONTooLarge(t *testing.T) {
	big := `{"value":"` + strings.Repeat("a", MaxBodyBytes+1024) + `"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(big))

	var dst map[string]any
	if DecodeJSON(rec, req, &dst) {
		t.Fatal("DecodeJSON accepted a body over the limit")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	env := decodeEnvelope(t, rec.Body.Bytes())
	if env.Error.Code != CodeBodyTooLarge {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeBodyTooLarge)
	}
}

func TestDecodeJSONAtLimitIsAccepted(t *testing.T) {
	// A body exactly at the limit must pass: the limit is 1 MiB inclusive.
	value := strings.Repeat("a", MaxBodyBytes-32)
	body := `{"value":"` + value + `"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(body))

	var dst map[string]any
	if !DecodeJSON(rec, req, &dst) {
		t.Fatalf("DecodeJSON rejected a body at the limit: %d %s", rec.Code, rec.Body)
	}
}

func TestDecodeJSONOptionalEmptyBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/test", strings.NewReader(""))

	var dst map[string]any
	if !DecodeJSONOptional(rec, req, &dst) {
		t.Fatalf("DecodeJSONOptional rejected an empty body: %s", rec.Body)
	}
}

func TestRoutePattern(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/envs/e/secrets", nil)
	if got := RoutePattern(req); got != "" {
		t.Errorf("RoutePattern before WithRoutePattern = %q, want empty", got)
	}

	req = WithRoutePattern(req, "GET /api/v1/projects/{p}/envs/{e}/secrets")
	if got := RoutePattern(req); got != "GET /api/v1/projects/{p}/envs/{e}/secrets" {
		t.Errorf("RoutePattern = %q", got)
	}
}

// TestDecodeJSONRejectsInvalidUTF8 pins SPEC §3: a value's bytes must be stored and
// returned exactly. encoding/json silently replaces invalid UTF-8 and unpaired
// UTF-16 surrogates with U+FFFD, which would store a value the caller never sent.
func TestDecodeJSONRejectsInvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{"lone high surrogate", `{"value":"a\ud800b"}`, false},
		{"lone low surrogate", `{"value":"a\udc00b"}`, false},
		{"surrogate pair is valid", `{"value":"a\ud83d\ude00b"}`, true},
		{"plain ascii", `{"value":"plain"}`, true},
		{"valid multibyte", `{"value":"héllo→"}`, true},
		// A raw invalid byte (0xED 0xA0 0x80 is an encoded surrogate, illegal in UTF-8).
		{"raw invalid utf8", "{\"value\":\"a\xed\xa0\x80b\"}", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(tt.body))

			var dst map[string]string
			got := DecodeJSON(rec, req, &dst)

			if got != tt.ok {
				t.Fatalf("DecodeJSON = %v, want %v (status %d, body %s)", got, tt.ok, rec.Code, rec.Body)
			}
			if !tt.ok {
				if rec.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", rec.Code)
				}
				env := decodeEnvelope(t, rec.Body.Bytes())
				if env.Error.Code != CodeValidation {
					t.Errorf("code = %q, want %q", env.Error.Code, CodeValidation)
				}
			}
			// A valid value must round-trip byte-exactly.
			if tt.ok && dst["value"] == "" && tt.body != `{"value":""}` {
				t.Errorf("value did not decode: %+v", dst)
			}
		})
	}
}

// TestDecodeJSONPreservesValueBytes pins that a legitimate value survives decoding
// unchanged, including characters that JSON escapes.
func TestDecodeJSONPreservesValueBytes(t *testing.T) {
	const want = "line1\nline2\ttab \"quoted\" \\slash → émoji 😀"

	body, err := json.Marshal(map[string]string{"value": want})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", bytes.NewReader(body))

	var dst map[string]string
	if !DecodeJSON(rec, req, &dst) {
		t.Fatalf("DecodeJSON rejected a valid body: %s", rec.Body)
	}
	if dst["value"] != want {
		t.Errorf("value changed:\n got %q\nwant %q", dst["value"], want)
	}
}
