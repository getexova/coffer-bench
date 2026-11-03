package main

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
	"time"
)

// requestTimeout bounds one CLI request. `coffer run` and exports of large
// environments are the slowest cases and still finish well inside it.
const requestTimeout = 60 * time.Second

// maxResponseBytes bounds what the CLI will read from the server, so a
// misbehaving server cannot exhaust the caller's memory.
const maxResponseBytes = 32 << 20 // 32 MiB

// client is a thin HTTP client for /api/v1. It never logs a request body: those
// carry secret values and passwords.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base, token string) *client {
	return &client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http: &http.Client{
			Timeout: requestTimeout,
			// Never follow a redirect: the API has no redirects, and following
			// one would replay a credential to wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// response is one HTTP exchange.
type response struct {
	status int
	ctype  string
	body   []byte
}

// getJSON performs a GET and decodes a 2xx JSON body into out.
func (c *client) getJSON(path string, query url.Values, out any) error {
	return c.doJSON(http.MethodGet, path, query, nil, out)
}

// sendJSON performs a request with an optional JSON body and decodes a 2xx JSON
// body into out.
func (c *client) sendJSON(method, path string, query url.Values, body, out any) error {
	return c.doJSON(method, path, query, body, out)
}

func (c *client) doJSON(method, path string, query url.Values, body, out any) error {
	resp, err := c.do(method, path, query, body)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(resp.body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(resp.body))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	return nil
}

// raw performs a request and returns the bytes exactly as received, for exports
// and single-value reads where the bytes must not be re-encoded.
func (c *client) raw(method, path string, query url.Values, body any) (*response, error) {
	return c.do(method, path, query, body)
}

// do performs one request and maps a non-2xx response onto an *apiError. A 202
// is not an error here: the caller decides, because a pending write is a
// documented outcome rather than a failure.
func (c *client) do(method, path string, query url.Values, body any) (*response, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cannot encode the request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, u, reader)
	if err != nil {
		return nil, fmt.Errorf("cannot build the request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("cannot read the server response: %w", err)
	}
	out := &response{
		status: resp.StatusCode,
		ctype:  resp.Header.Get("Content-Type"),
		body:   data,
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return out, nil
	}
	return nil, decodeAPIError(resp.StatusCode, data)
}

// decodeAPIError reads {"error":{"code","message"}} (docs/CONTRACTS.md §2). A
// body that does not match still maps by status, with a generic message.
func decodeAPIError(status int, body []byte) *apiError {
	e := &apiError{Status: status}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		e.Code = envelope.Error.Code
		e.Message = envelope.Error.Message
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	return e
}

// transportError turns a dial failure into a message that says what to check,
// without leaking anything about the credential.
func transportError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("the server did not respond in time: %w", err)
	}
	return fmt.Errorf("cannot reach the server: %w", err)
}

// values builds a query string, skipping empty values.
func values(pairs ...string) url.Values {
	q := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			q.Set(pairs[i], pairs[i+1])
		}
	}
	return q
}

// escapePath escapes one path segment. Slugs and keys are validated before they
// reach this, and the escaping is the second line of defence: no value is ever
// placed in a URL (SPEC §4).
func escapePath(segment string) string {
	return url.PathEscape(segment)
}

// envPath builds /projects/{p}/envs/{e}.
func envPath(project, env string) string {
	return "/api/v1/projects/" + escapePath(project) + "/envs/" + escapePath(env)
}

// secretPath builds /projects/{p}/envs/{e}/secrets/{key}.
func secretPath(project, env, key string) string {
	return envPath(project, env) + "/secrets/" + escapePath(key)
}
