package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxResponseBytes = 64 << 20 // 64 MiB

// client is a minimal Coffer API client.
type client struct {
	app   *App
	base  string // e.g. http://127.0.0.1:8420 (no trailing slash)
	token string
	hc    *http.Client
}

type response struct {
	status      int
	body        []byte
	contentType string
}

// newClient builds a client. If needAuth is true and no token is available,
// it fails with exit 3 before any request is made.
func (c *ctx) newClient(needAuth bool) (*client, error) {
	a := c.app
	var cfg *config
	token, fromEnv := a.envToken()
	if !fromEnv {
		var err error
		cfg, err = a.loadConfig()
		if err != nil {
			return nil, err
		}
		token = cfg.Token
	}
	base, err := a.resolveURL(c.flag("url"), cfg)
	if err != nil {
		return nil, err
	}
	if needAuth {
		if token == "" {
			if fromEnv {
				return nil, &cliError{code: ExitUnauth, errCode: "unauthenticated", msg: "COFFER_TOKEN is empty"}
			}
			return nil, &cliError{code: ExitUnauth, errCode: "unauthenticated", msg: "not logged in (run `coffer login --email EMAIL`, or set COFFER_TOKEN)"}
		}
		if !validTokenChars(token) {
			return nil, &cliError{code: ExitUnauth, errCode: "unauthenticated", msg: "token contains invalid characters"}
		}
	} else {
		token = ""
	}
	return a.makeClient(base, token), nil
}

func (a *App) makeClient(base, token string) *client {
	tr := a.Transport
	if tr == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   a.Timeout,
		// Never follow redirects: a redirect could carry the bearer token to
		// another origin, and the API never redirects legitimately.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &client{app: a, base: base, token: token, hc: hc}
}

func validTokenChars(t string) bool {
	for i := 0; i < len(t); i++ {
		if t[i] <= 0x20 || t[i] >= 0x7f {
			return false
		}
	}
	return true
}

// seg escapes a user-supplied value for use as a single path segment.
// "." and ".." (and empty) are rejected because they would be resolved as
// relative path segments by the server's router.
func seg(name, v string) (string, error) {
	if v == "" || v == "." || v == ".." {
		return "", validationErr("invalid %s %q", name, v)
	}
	return url.PathEscape(v), nil
}

// do performs an API request. path is relative to /api/v1 and must already be
// escaped. body (if non-nil) is JSON-encoded. Non-2xx responses become
// *cliError with the mapped exit code.
func (cl *client) do(method, path string, query url.Values, body any) (*response, error) {
	u := cl.base + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(body); err != nil {
			return nil, genericErr("cannot encode request")
		}
		rdr = &buf
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, genericErr("cannot build request to %s", cl.base)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "coffer-cli/"+Version)
	if cl.token != "" {
		req.Header.Set("Authorization", "Bearer "+cl.token)
	}
	resp, err := cl.hc.Do(req)
	if err != nil {
		return nil, connErr(cl.base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, genericErr("error reading response from %s", cl.base)
	}
	if len(data) > maxResponseBytes {
		return nil, genericErr("response from server too large")
	}
	r := &response{status: resp.StatusCode, body: data, contentType: resp.Header.Get("Content-Type")}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return r, apiError(r)
	}
	return r, nil
}

// connErr describes a transport failure without echoing request details.
func connErr(base string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &cliError{code: ExitError, errCode: "connection", msg: fmt.Sprintf("request to %s timed out", base)}
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return &cliError{code: ExitError, errCode: "connection", msg: fmt.Sprintf("cannot connect to %s: %v", base, oe.Err)}
	}
	return &cliError{code: ExitError, errCode: "connection", msg: fmt.Sprintf("cannot connect to %s: %v", base, err)}
}

// exitForStatus maps an HTTP status to a CLI exit code (SPEC §7.1).
func exitForStatus(status int) int {
	switch status {
	case 401:
		return ExitUnauth
	case 403:
		return ExitForbidden
	case 404:
		return ExitNotFound
	case 400, 413, 422:
		return ExitValidation
	case 409:
		return ExitConflict
	case 429:
		return ExitRateLimited
	}
	if status >= 200 && status <= 299 {
		return ExitOK
	}
	return ExitError
}

type apiErrorBody struct {
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func apiError(r *response) *cliError {
	ce := &cliError{code: exitForStatus(r.status), errCode: fmt.Sprintf("http_%d", r.status)}
	var b apiErrorBody
	if err := json.Unmarshal(r.body, &b); err == nil && b.Error != nil && (b.Error.Code != "" || b.Error.Message != "") {
		ce.errCode = b.Error.Code
		msg := b.Error.Message
		if msg == "" {
			msg = http.StatusText(r.status)
		}
		ce.rawMsg = msg
		if b.Error.Code != "" {
			ce.msg = fmt.Sprintf("%s (%s)", msg, b.Error.Code)
		} else {
			ce.msg = msg
			ce.errCode = fmt.Sprintf("http_%d", r.status)
		}
		return ce
	}
	ce.msg = fmt.Sprintf("HTTP %d", r.status)
	return ce
}

// decode unmarshals a successful JSON response.
func (r *response) decode(v any) error {
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return genericErr("unexpected response from server")
	}
	return nil
}

// strings.Builder helper used by request paths.
func joinPath(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(p)
	}
	return b.String()
}
