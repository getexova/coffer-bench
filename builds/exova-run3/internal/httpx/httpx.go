// Package httpx is the single source of the API's wire behaviour: the error
// envelope, the error codes and their status mapping, the response headers, and
// the request body limit (docs/CONTRACTS.md §2).
//
// Response headers are set by this package rather than by handlers, so a handler
// cannot forget them. Every helper here writes `Content-Type`,
// `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` before the status
// line; `X-Request-Id` is written by the request-id middleware for every response,
// including errors and panics.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"
)

// MaxBodyBytes is the request body limit. A larger body is rejected with 413.
const MaxBodyBytes = 1 << 20

// Error codes (docs/CONTRACTS.md §2). No slice invents another one.
const (
	CodeValidation      = "validation_error"
	CodeUnauthenticated = "unauthenticated"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeBodyTooLarge    = "body_too_large"
	CodeRateLimited     = "rate_limited"
	CodeInternal        = "internal_error"
)

// InternalMessage is the literal message returned for any unexpected error.
const InternalMessage = "internal error"

// statusByCode is the frozen code-to-status mapping.
var statusByCode = map[string]int{
	CodeValidation:      http.StatusBadRequest,
	CodeUnauthenticated: http.StatusUnauthorized,
	CodeForbidden:       http.StatusForbidden,
	CodeNotFound:        http.StatusNotFound,
	CodeConflict:        http.StatusConflict,
	CodeBodyTooLarge:    http.StatusRequestEntityTooLarge,
	CodeRateLimited:     http.StatusTooManyRequests,
	CodeInternal:        http.StatusInternalServerError,
}

// StatusFor maps an error code to its HTTP status. An unknown code is a 500: it
// means a slice invented a code, and that must never leak as a success status.
func StatusFor(code string) int {
	if status, ok := statusByCode[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// Error is an API error carrying a frozen code and a stable, generic message.
// Err holds the underlying cause for the server log only; it is never serialised
// and never sent to the client.
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the cause to errors.Is/errors.As.
func (e *Error) Unwrap() error { return e.Err }

// WithMessage returns a copy of e carrying msg. It is how a handler adds a
// specific, still generic, message without mutating a shared value.
func WithMessage(e *Error, msg string) *Error {
	if e == nil {
		return Internal(nil)
	}
	clone := *e
	clone.Message = msg
	return &clone
}

// Validation builds a 400 validation_error.
func Validation(msg string) *Error { return &Error{Code: CodeValidation, Message: msg} }

// Unauthenticated builds a 401 unauthenticated.
func Unauthenticated(msg string) *Error { return &Error{Code: CodeUnauthenticated, Message: msg} }

// Forbidden builds a 403 forbidden.
func Forbidden(msg string) *Error { return &Error{Code: CodeForbidden, Message: msg} }

// NotFound builds a 404 not_found. Use it for every invisible resource: the body
// must be identical whether the resource is missing or merely out of reach.
func NotFound(msg string) *Error { return &Error{Code: CodeNotFound, Message: msg} }

// Conflict builds a 409 conflict.
func Conflict(msg string) *Error { return &Error{Code: CodeConflict, Message: msg} }

// TooLarge builds a 413 body_too_large.
func TooLarge(msg string) *Error { return &Error{Code: CodeBodyTooLarge, Message: msg} }

// RateLimited builds a 429 rate_limited.
func RateLimited(msg string) *Error { return &Error{Code: CodeRateLimited, Message: msg} }

// Internal builds a 500 internal_error. The message is always the literal
// "internal error", so a database error can never surface SQL text.
func Internal(err error) *Error {
	return &Error{Code: CodeInternal, Message: InternalMessage, Err: err}
}

// errorBody is the only error shape the API emits.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// setCommonHeaders writes the headers every API response carries. Call it before
// WriteHeader.
func setCommonHeaders(w http.ResponseWriter, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	// No CORS headers are ever emitted; make that explicit for any future reader.
	h.Del("Access-Control-Allow-Origin")
}

// WriteJSON writes v as JSON with the common headers. A marshal failure is turned
// into a 500 envelope rather than a truncated body.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		slog.Error("httpx: marshal response", "error", err)
		writeRaw(w, http.StatusInternalServerError, "application/json", mustEnvelope(CodeInternal, InternalMessage))
		return
	}
	writeRaw(w, status, "application/json", buf)
}

// WriteText writes a non-JSON body (a dotenv export) while keeping the security
// headers. Only Content-Type differs from WriteJSON.
func WriteText(w http.ResponseWriter, status int, contentType string, body []byte) {
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	writeRaw(w, status, contentType, body)
}

func writeRaw(w http.ResponseWriter, status int, contentType string, body []byte) {
	setCommonHeaders(w, contentType)
	w.WriteHeader(status)
	if len(body) == 0 {
		return
	}
	if _, err := w.Write(body); err != nil {
		// The client went away mid-write; there is nothing left to tell it.
		slog.Debug("httpx: write response", "error", err)
	}
}

// WriteErrorCode writes an error envelope from a code and message.
func WriteErrorCode(w http.ResponseWriter, status int, code, msg string) {
	writeRaw(w, status, "application/json", mustEnvelope(code, msg))
}

// WriteError writes err as the error envelope. A *Error keeps its code; anything
// else becomes a 500 whose message is the literal "internal error", with the cause
// logged server-side and never sent.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr == nil {
		logServerError(r, err)
		writeRaw(w, http.StatusInternalServerError, "application/json", mustEnvelope(CodeInternal, InternalMessage))
		return
	}

	if apiErr.Code == CodeInternal {
		cause := apiErr.Err
		if cause == nil {
			cause = errors.New(apiErr.Message)
		}
		logServerError(r, cause)
	}

	code := apiErr.Code
	status := StatusFor(code)
	if status == http.StatusInternalServerError {
		// An unknown code is a programming error; do not echo it to the client.
		code = CodeInternal
	}
	msg := apiErr.Message
	if code == CodeInternal {
		msg = InternalMessage
	}
	if msg == "" {
		msg = defaultMessage(code)
	}
	writeRaw(w, status, "application/json", mustEnvelope(code, msg))
}

func defaultMessage(code string) string {
	switch code {
	case CodeValidation:
		return "request is invalid"
	case CodeUnauthenticated:
		return "authentication required"
	case CodeForbidden:
		return "not permitted"
	case CodeNotFound:
		return "not found"
	case CodeConflict:
		return "conflict"
	case CodeBodyTooLarge:
		return "request body too large"
	case CodeRateLimited:
		return "too many requests"
	default:
		return InternalMessage
	}
}

func logServerError(r *http.Request, err error) {
	if err == nil {
		return
	}
	attrs := []any{"error", err.Error()}
	if r != nil {
		if route := RoutePattern(r); route != "" {
			attrs = append(attrs, "route", route)
		}
	}
	slog.Error("request failed", attrs...)
}

func mustEnvelope(code, msg string) []byte {
	buf, err := json.Marshal(errorBody{Error: errorDetail{Code: code, Message: msg}})
	if err != nil {
		// Static strings and a struct of two strings cannot fail to marshal.
		return []byte(`{"error":{"code":"internal_error","message":"internal error"}}`)
	}
	return buf
}

// routePatternKey carries the matched ServeMux pattern in the request context so
// logging and error reporting can name the route instead of the raw path.
type routePatternKey struct{}

// WithRoutePattern records the matched route pattern on the request.
func WithRoutePattern(r *http.Request, pattern string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), routePatternKey{}, pattern))
}

// RoutePattern returns the matched route pattern, or "" when unknown.
func RoutePattern(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v, ok := r.Context().Value(routePatternKey{}).(string); ok {
		return v
	}
	return ""
}

// DecodeJSON decodes a JSON request body into dst under the 1 MiB limit. It
// returns false when it has already written the response: 413 body_too_large for a
// body over the limit, 400 validation_error for malformed JSON or a trailing
// document. Unknown fields are rejected so a field the caller may not set is a 400
// rather than a silent no-op.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		WriteError(w, r, Validation("request body is required"))
		return false
	}

	body, ok := readBody(w, r)
	if !ok {
		return false
	}

	// Reject a body that is not valid UTF-8 before encoding/json sees it.
	//
	// A JSON string may legally carry a lone UTF-16 surrogate (\ud800 with no low
	// surrogate) and invalid UTF-8 bytes are accepted too. encoding/json silently
	// replaces both with U+FFFD, so a secret value would be stored as something the
	// caller never sent: "a\ud800b" arrives as the bytes 61efbfbd62. SPEC §3 requires
	// a value's bytes to be stored and returned exactly, so the only correct answer
	// at this boundary is a 400.
	//
	// The check runs on the raw bytes, not on the decoded string, because by then the
	// information is already gone.
	if !utf8.Valid(body) {
		WriteError(w, r, Validation("request body must be valid UTF-8"))
		return false
	}
	if hasLoneSurrogate(body) {
		WriteError(w, r, Validation("request body contains an unpaired UTF-16 surrogate escape"))
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			WriteError(w, r, Validation("request body is required"))
			return false
		}
		WriteError(w, r, Validation("request body is not valid JSON"))
		return false
	}

	// Exactly one JSON document per request.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		WriteError(w, r, Validation("request body must contain a single JSON object"))
		return false
	}

	return true
}

// readBody reads the request body under the 1 MiB limit, writing the response and
// returning false when it is too large or unreadable.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limited := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			WriteError(w, r, TooLarge("request body exceeds 1 MiB"))
			return nil, false
		}
		WriteError(w, r, Validation("could not read request body"))
		return nil, false
	}
	return body, true
}

// hasLoneSurrogate reports whether a JSON body contains a \uD800-\uDFFF escape that
// is not part of a valid surrogate pair.
//
// encoding/json turns an unpaired one into U+FFFD without complaint, which silently
// alters a value. The scan is deliberately simple and only looks at escapes outside
// of strings it can skip, so it cannot reject valid input.
func hasLoneSurrogate(body []byte) bool {
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			continue
		}
		// Count preceding backslashes to tell an escape from an escaped backslash.
		backslashes := 0
		for j := i; j >= 0 && body[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			continue
		}
		if i+5 >= len(body) || body[i+1] != 'u' {
			continue
		}
		code, ok := parseHex4(body[i+2 : i+6])
		if !ok {
			continue
		}
		switch {
		case code >= 0xD800 && code <= 0xDBFF:
			// High surrogate: the next escape must be a low surrogate.
			if i+11 >= len(body) || body[i+6] != '\\' || body[i+7] != 'u' {
				return true
			}
			next, ok := parseHex4(body[i+8 : i+12])
			if !ok || next < 0xDC00 || next > 0xDFFF {
				return true
			}
			i += 11 // consume the pair
		case code >= 0xDC00 && code <= 0xDFFF:
			// A low surrogate with no preceding high surrogate.
			return true
		}
	}
	return false
}

// parseHex4 decodes four hex digits, reporting whether they were valid.
func parseHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var out rune
	for _, c := range b[:4] {
		out <<= 4
		switch {
		case c >= '0' && c <= '9':
			out |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			out |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			out |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return out, true
}

// DecodeJSONOptional is DecodeJSON for a body that may be absent: an empty body
// leaves dst untouched and succeeds. It is used by DELETE routes that accept no
// payload.
func DecodeJSONOptional(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	body, ok := readBody(w, r)
	if !ok {
		return false
	}
	if len(body) == 0 {
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return DecodeJSON(w, r, dst)
}
