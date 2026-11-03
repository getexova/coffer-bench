// Package api implements Coffer's HTTP API (CONTRACT §5).
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

// MaxBody is the request body limit (1 MiB).
const MaxBody = 1 << 20

// Server is the HTTP API. Create it with New, then call SetReady once the
// boot sequence has finished.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	hasher *crypto.Hasher

	pool     *pgxpool.Pool
	appender *audit.Appender
	ready    atomic.Bool
	migOK    atomic.Value // time.Time of the last successful migration check

	mux *http.ServeMux

	bg        sync.WaitGroup
	lastUsed  sync.Map     // token id -> time.Time (throttle for last_used_at)
	lastPrune atomic.Int64 // unix nanos of the last login_failures prune
}

// New builds the server. It serves /healthz immediately; /readyz and the API
// answer 503 until SetReady.
func New(cfg *config.Config, log *slog.Logger, hasher *crypto.Hasher) *Server {
	s := &Server{cfg: cfg, log: log, hasher: hasher, mux: http.NewServeMux()}
	s.routes()
	return s
}

// SetReady installs the request pool and marks the API ready.
func (s *Server) SetReady(pool *pgxpool.Pool) {
	s.pool = pool
	s.appender = audit.NewAppender(pool)
	s.ready.Store(true)
}

// Close waits for background work (audit flushes, last-used updates).
func (s *Server) Close() {
	s.ready.Store(false)
	if s.appender != nil {
		s.appender.Close()
	}
	s.bg.Wait()
}

// ---------------------------------------------------------------- context

type ctxKey int

const infoKey ctxKey = 1

// reqInfo is per-request state shared between the middleware and handlers.
type reqInfo struct {
	id      string
	route   string
	actor   string
	handled bool
	body    []byte
	start   time.Time
}

func info(r *http.Request) *reqInfo {
	if v, ok := r.Context().Value(infoKey).(*reqInfo); ok {
		return v
	}
	return &reqInfo{}
}

// ---------------------------------------------------------------- errors

type apiError struct {
	status  int
	code    string
	message string
}

var (
	errNotFound     = &apiError{http.StatusNotFound, "not_found", "not found"}
	errForbidden    = &apiError{http.StatusForbidden, "forbidden", "forbidden"}
	errUnauth       = &apiError{http.StatusUnauthorized, "unauthenticated", "authentication required"}
	errBadCreds     = &apiError{http.StatusUnauthorized, "unauthenticated", "invalid credentials"}
	errInternal     = &apiError{http.StatusInternalServerError, "internal", "internal error"}
	errUnavailable  = &apiError{http.StatusServiceUnavailable, "unavailable", "service not ready"}
	errTooLarge     = &apiError{http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large"}
	errRateLimited  = &apiError{http.StatusTooManyRequests, "rate_limited", "too many failed login attempts; try again later"}
	errMethod       = &apiError{http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed"}
	errPwChangeReqd = &apiError{http.StatusForbidden, "password_change_required", "password change required"}
)

func badRequest(msg string) *apiError {
	return &apiError{http.StatusBadRequest, "validation", msg}
}

func conflict(msg string) *apiError {
	return &apiError{http.StatusConflict, "conflict", msg}
}

func writeError(w http.ResponseWriter, e *apiError) {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": e.code, "message": e.message}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		writeError(w, errInternal)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// internalError logs err with the request id and answers 500 without detail.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "request_id", info(r).id, "route", info(r).route, "error", err.Error())
	writeError(w, errInternal)
}

// ---------------------------------------------------------------- middleware

type captureWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (c *captureWriter) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.status = code
	c.wrote = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// fallbackWriter swallows the output of the stock ServeMux 404/405/redirect
// handlers so we can answer with our JSON body instead.
type fallbackWriter struct {
	h      http.Header
	status int
}

func (f *fallbackWriter) Header() http.Header { return f.h }
func (f *fallbackWriter) WriteHeader(code int) {
	if f.status == 0 {
		f.status = code
	}
}
func (f *fallbackWriter) Write(b []byte) (int, error) {
	if f.status == 0 {
		f.status = http.StatusOK
	}
	return len(b), nil
}

func newRequestID() string { return hex.EncodeToString(crypto.RandomBytes(16)) }

// ServeHTTP is the outermost handler: request id, security headers, panic
// recovery, body limit, routing with JSON 404/405, and the request log.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ri := &reqInfo{id: newRequestID(), route: "unmatched", start: time.Now()}
	h := w.Header()
	h.Set("X-Request-Id", ri.id)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Content-Type", "application/json")
	cw := &captureWriter{ResponseWriter: w}
	r = r.WithContext(context.WithValue(r.Context(), infoKey, ri))

	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			s.log.Error("panic recovered", "request_id", ri.id, "route", ri.route, "panic_type", fmt.Sprintf("%T", p))
			if !cw.wrote {
				writeError(cw, errInternal)
			}
		}
		status := cw.status
		if !cw.wrote {
			status = http.StatusOK
		}
		attrs := []any{
			"method", sanitizeMethod(r.Method), "route", ri.route, "status", status,
			"duration_ms", float64(time.Since(ri.start).Microseconds()) / 1000.0, "request_id", ri.id,
		}
		if ri.actor != "" {
			attrs = append(attrs, "actor", ri.actor)
		}
		s.log.Info("request", attrs...)
	}()

	// Body limit, applied to every route.
	if r.ContentLength > MaxBody {
		writeError(cw, errTooLarge)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(http.MaxBytesReader(cw, r.Body, MaxBody))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeError(cw, errTooLarge)
			} else {
				writeError(cw, badRequest("could not read request body"))
			}
			return
		}
		ri.body = body
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	if !strings.HasPrefix(r.URL.Path, "/") {
		// "OPTIONS *" and other non-origin-form request targets.
		writeError(cw, errNotFound)
		return
	}
	dispatch(s.mux, cw, r)
}

func sanitizeMethod(m string) string {
	if len(m) > 16 {
		m = m[:16]
	}
	for _, c := range m {
		if c < 'A' || c > 'Z' {
			return "OTHER"
		}
	}
	return m
}

// dispatch routes r within mux, converting the stock 404/405/redirect
// responses into JSON errors.
func dispatch(mux *http.ServeMux, w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	_, pattern := mux.Handler(r)
	if pattern != "" {
		// Our wrapper sets ri.handled before writing; a stock redirect
		// handler (non-canonical path) never does.
		probe := &probeWriter{ResponseWriter: w, ri: ri, fw: &fallbackWriter{h: http.Header{}}}
		mux.ServeHTTP(probe, r)
		if !ri.handled {
			writeError(w, errNotFound)
		}
		return
	}
	fw := &fallbackWriter{h: http.Header{}}
	mux.ServeHTTP(fw, r)
	if fw.status == http.StatusMethodNotAllowed {
		if allow := fw.h.Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		writeError(w, errMethod)
		return
	}
	writeError(w, errNotFound)
}

// probeWriter forwards to the real writer once our handler has claimed the
// request (ri.handled); before that (stock redirect handler) output goes to
// the fallback sink.
type probeWriter struct {
	http.ResponseWriter
	ri *reqInfo
	fw *fallbackWriter
}

func (p *probeWriter) Header() http.Header {
	if p.ri.handled {
		return p.ResponseWriter.Header()
	}
	return p.fw.Header()
}
func (p *probeWriter) WriteHeader(code int) {
	if p.ri.handled {
		p.ResponseWriter.WriteHeader(code)
		return
	}
	p.fw.WriteHeader(code)
}
func (p *probeWriter) Write(b []byte) (int, error) {
	if p.ri.handled {
		return p.ResponseWriter.Write(b)
	}
	return p.fw.Write(b)
}

// ---------------------------------------------------------------- routing

type principalHandler func(w http.ResponseWriter, r *http.Request, p *Principal)

var wildcardRE = regexp.MustCompile(`\{([a-z_]+)\}`)

type routeOpts struct {
	public          bool // no authentication
	allowPwRequired bool // reachable while must_change_password
}

// handle registers an API route. pattern is "METHOD /path" relative to /api/v1.
func (s *Server) handle(pattern string, opts routeOpts, h principalHandler) {
	method, path, _ := strings.Cut(pattern, " ")
	full := method + " /api/v1" + path
	names := wildcardRE.FindAllStringSubmatch(path, -1)
	s.mux.HandleFunc(full, func(w http.ResponseWriter, r *http.Request) {
		ri := info(r)
		ri.handled = true
		ri.route = full
		if !s.ready.Load() {
			writeError(w, errUnavailable)
			return
		}
		var tb strings.Builder
		tb.WriteString(method + " " + path)
		for _, n := range names {
			tb.WriteString(" " + n[1] + "=" + r.PathValue(n[1]))
		}
		ctx := context.WithValue(r.Context(), targetKey, tb.String())
		r = r.WithContext(ctx)
		if opts.public {
			h(w, r, nil)
			return
		}
		p, apiErr := s.authenticate(r)
		if apiErr != nil {
			writeError(w, apiErr)
			return
		}
		ri.actor = p.ActorID()
		if s.cfg.RequirePasswordChange && p.Kind != KindService && p.MustChangePassword && !opts.allowPwRequired {
			s.audit(r, p, "authz.denied", deniedTarget(r), audit.Denied, map[string]any{"status": 403, "reason": "password_change_required"})
			writeError(w, errPwChangeReqd)
			return
		}
		h(w, r, p)
	})
}

const targetKey ctxKey = 2

// deniedTarget is the audit target for authz denials: the method, route
// pattern and the identifiers exactly as given in the request.
func deniedTarget(r *http.Request) string {
	if v, ok := r.Context().Value(targetKey).(string); ok {
		return v
	}
	return r.Method + " unmatched"
}

// ---------------------------------------------------------------- helpers

// clientIP returns the source IP per CONTRACT §5.1.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

// decodeBody strictly decodes the buffered JSON object body into dst.
func decodeBody(r *http.Request, dst any) *apiError {
	body := info(r).body
	if len(bytes.TrimSpace(body)) == 0 {
		return badRequest("request body required")
	}
	if !utf8.Valid(body) {
		return badRequest("request body must be valid UTF-8")
	}
	if hasLoneSurrogate(body) {
		return badRequest("request body contains an invalid unicode escape")
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return badRequest("request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return badRequest(jsonErrMessage(err))
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return badRequest("unexpected data after JSON object")
	}
	return nil
}

func jsonErrMessage(err error) string {
	var ute *json.UnmarshalTypeError
	switch {
	case errors.As(err, &ute):
		if ute.Field != "" {
			return "invalid type for field " + safeField(ute.Field)
		}
		return "invalid JSON type"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown field " + safeField(strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`))
	default:
		return "invalid JSON"
	}
}

func safeField(f string) string {
	if len(f) > 64 {
		f = f[:64]
	}
	var b strings.Builder
	for _, c := range f {
		if c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return `"` + b.String() + `"`
}

// hasLoneSurrogate reports whether a JSON text contains a \uD800-\uDFFF escape
// that is not part of a valid surrogate pair (encoding/json would silently
// replace it with U+FFFD, changing the stored bytes).
func hasLoneSurrogate(b []byte) bool {
	hex4 := func(i int) (rune, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		var v rune
		for _, c := range b[i : i+4] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				v |= rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= rune(c-'A') + 10
			default:
				return 0, false
			}
		}
		return v, true
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			continue
		}
		if b[i+1] != 'u' {
			i++ // skip the escaped character (handles "\\u")
			continue
		}
		v, ok := hex4(i + 2)
		if !ok {
			i++
			continue
		}
		switch {
		case v >= 0xD800 && v <= 0xDBFF:
			if i+7 < len(b) && b[i+6] == '\\' && b[i+7] == 'u' {
				if lo, ok := hex4(i + 8); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 11
					continue
				}
			}
			return true
		case v >= 0xDC00 && v <= 0xDFFF:
			return true
		}
		i += 5
	}
	return false
}

// ts formats a timestamp per CONTRACT §5.1.
func ts(t time.Time) string { return t.UTC().Format(audit.TSFormat) }

func tsPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := ts(*t)
	return &s
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var keyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

var idRE = regexp.MustCompile(`^[a-z]{3}_[a-z2-7]{32}$`)

// validID reports whether s looks like one of our opaque ids. Malformed ids
// (which could also carry NUL or invalid UTF-8 into SQL) are simply "not found".
func validID(s string) bool { return idRE.MatchString(s) }

// ValidSlug reports whether s is a valid org/project/env slug.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// ValidKey reports whether s is a valid secret key.
func ValidKey(s string) bool { return keyRE.MatchString(s) }
