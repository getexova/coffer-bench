package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// secretBase returns the escaped /projects/{p}/envs/{e} prefix.
func secretBase(c *ctx) (string, error) {
	ps, err := seg("project", c.flag("project"))
	if err != nil {
		return "", err
	}
	es, err := seg("env", c.flag("env"))
	if err != nil {
		return "", err
	}
	return joinPath("projects", ps, "envs", es), nil
}

func secretPath(c *ctx, key string, rest ...string) (string, error) {
	base, err := secretBase(c)
	if err != nil {
		return "", err
	}
	ks, err := seg("key", key)
	if err != nil {
		return "", err
	}
	return base + joinPath(append([]string{"secrets", ks}, rest...)...), nil
}

func cmdSecretsList(c *ctx) error {
	base, err := secretBase(c)
	if err != nil {
		return err
	}
	return listCmd(c, base+"/secrets", nil, []column{col("KEY", "key"), col("VERSION", "version"), col("UPDATED_AT", "updated_at"), col("UPDATED_BY", "updated_by")})
}

func cmdSecretsGet(c *ctx) error {
	rest := []string{}
	if c.has("version") {
		n, _, err := c.intFlag("version")
		if err != nil {
			return err
		}
		rest = append(rest, "versions", strconv.FormatInt(n, 10))
	}
	path, err := secretPath(c, c.args[0], rest...)
	if err != nil {
		return err
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("GET", path, nil, nil)
	if err != nil {
		return err
	}
	var v struct {
		Value *string `json:"value"`
	}
	if err := resp.decode(&v); err != nil {
		return err
	}
	if v.Value == nil {
		return genericErr("unexpected response from server")
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	out := *v.Value
	if c.app.StdoutIsTTY() {
		out += "\n"
	}
	_, err = c.out().Write([]byte(out))
	return err
}

// writeResult handles 200 {version} and 202 {change_id} write responses.
func writeResult(c *ctx, resp *response, verb, key string) error {
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	if resp.status == 202 {
		id := str(m, "change_id")
		if id == "" {
			return genericErr("unexpected response from server")
		}
		if c.json() {
			if err := writeJSON(c.out(), map[string]string{"status": "pending", "change_id": id}); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(c.out(), "pending approval: change %s\n", sanitize(id))
		}
		return exitSilently(ExitPending)
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	fmt.Fprintf(c.out(), "%s %s (version %s)\n", verb, sanitize(key), sanitize(str(m, "version")))
	return nil
}

func cmdSecretsSet(c *ctx) error {
	key := c.args[0]
	path, err := secretPath(c, key)
	if err != nil {
		return err
	}
	body := map[string]any{}
	if c.has("expect-version") {
		n, _, err := c.intFlag("expect-version")
		if err != nil {
			return err
		}
		body["expected_version"] = n
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	var value string
	if len(c.args) == 2 {
		value = c.args[1]
		if !utf8.ValidString(value) {
			return validationErr("value is not valid UTF-8")
		}
		if len(value) > maxValueBytes {
			return validationErr("value exceeds %d bytes", maxValueBytes)
		}
	} else {
		if value, err = c.app.readValue(); err != nil {
			return err
		}
	}
	body["value"] = value
	resp, err := cl.do("PUT", path, nil, body)
	if err != nil {
		return err
	}
	return writeResult(c, resp, "set", key)
}

func cmdSecretsDelete(c *ctx) error {
	key := c.args[0]
	path, err := secretPath(c, key)
	if err != nil {
		return err
	}
	var q url.Values
	if c.has("expect-version") {
		n, _, err := c.intFlag("expect-version")
		if err != nil {
			return err
		}
		q = url.Values{"expected_version": {strconv.FormatInt(n, 10)}}
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("DELETE", path, q, nil)
	if err != nil {
		return err
	}
	return writeResult(c, resp, "deleted", key)
}

func cmdSecretsHistory(c *ctx) error {
	path, err := secretPath(c, c.args[0], "versions")
	if err != nil {
		return err
	}
	return listCmd(c, path, nil, []column{col("VERSION", "version"), col("DELETED", "deleted"), col("CREATED_AT", "created_at"), col("CREATED_BY", "created_by")})
}

func cmdSecretsRollback(c *ctx) error {
	key := c.args[0]
	path, err := secretPath(c, key, "rollback")
	if err != nil {
		return err
	}
	to, _, err := c.intFlag("to")
	if err != nil {
		return err
	}
	body := map[string]any{"to": to}
	if c.has("expect-version") {
		n, _, err := c.intFlag("expect-version")
		if err != nil {
			return err
		}
		body["expected_version"] = n
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("POST", path, nil, body)
	if err != nil {
		return err
	}
	return writeResult(c, resp, "rolled back", key)
}

var formatRe = regexp.MustCompile(`^[a-z]+$`)

func cmdSecretsExport(c *ctx) error {
	base, err := secretBase(c)
	if err != nil {
		return err
	}
	format := "json"
	if c.has("format") {
		format = c.flag("format")
	}
	if !formatRe.MatchString(format) {
		return validationErr("--format must be dotenv or json")
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("GET", base+"/export", url.Values{"format": {format}}, nil)
	if err != nil {
		return err
	}
	body := resp.body
	if format == "json" {
		if !json.Valid(body) {
			return genericErr("unexpected response from server")
		}
		body = bytes.TrimRight(body, " \t\r\n")
		body = append(body, '\n')
	}
	if c.json() && format != "json" {
		// --json promises exactly one JSON document on stdout, so a dotenv
		// body is wrapped; the content string is byte-exact (values are
		// UTF-8 per SPEC, so the JSON string round-trips losslessly).
		if !utf8.Valid(body) {
			return genericErr("unexpected response from server")
		}
		return writeJSON(c.out(), map[string]string{"format": format, "content": string(body)})
	}
	// dotenv (and any other server-supported format) is written byte-exact.
	_, err = c.out().Write(body)
	return err
}
