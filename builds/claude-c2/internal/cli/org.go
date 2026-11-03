package cli

import (
	"fmt"
	"net/url"
	"strings"
)

// ---- shared helpers ----

func (c *ctx) getList(cl *client, path string, q url.Values) (*response, []map[string]any, error) {
	resp, err := cl.do("GET", path, q, nil)
	if err != nil {
		return nil, nil, err
	}
	var rows []map[string]any
	if err := resp.decode(&rows); err != nil {
		return nil, nil, err
	}
	return resp, rows, nil
}

// listCmd GETs a list and prints it as JSON or a table.
func listCmd(c *ctx, path string, q url.Values, cols []column) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, rows, err := c.getList(cl, path, q)
	if err != nil {
		return err
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	printTable(c.out(), cols, rows)
	return nil
}

// simpleCmd performs a request and prints the JSON response or a message.
func simpleCmd(c *ctx, method, path string, body any, msg string) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do(method, path, nil, body)
	if err != nil {
		return err
	}
	if c.json() {
		return printJSONOr(c, resp, map[string]string{"status": "ok"})
	}
	fmt.Fprintln(c.out(), sanitize(msg))
	return nil
}

// lookupMember resolves an email to a user id via GET /members.
func lookupMember(cl *client, email string) (string, error) {
	resp, err := cl.do("GET", "/members", nil, nil)
	if err != nil {
		return "", err
	}
	var rows []map[string]any
	if err := resp.decode(&rows); err != nil {
		return "", err
	}
	want := strings.ToLower(strings.TrimSpace(email))
	for _, r := range rows {
		if strings.ToLower(strings.TrimSpace(str(r, "email"))) == want {
			if id := str(r, "id"); id != "" {
				return id, nil
			}
		}
	}
	return "", &cliError{code: ExitNotFound, errCode: "not_found", msg: fmt.Sprintf("no member with email %s", email)}
}

// ---- admin ----

func cmdAdminOrgCreate(c *ctx) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	slug := c.args[0]
	pw, err := c.app.readPassword("Owner password: ")
	if err != nil {
		return err
	}
	resp, err := cl.do("POST", "/admin/orgs", nil, map[string]string{"slug": slug, "owner_email": c.flag("owner-email"), "owner_password": pw})
	if err != nil {
		return err
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	owner, _ := m["owner"].(map[string]any)
	fmt.Fprintf(c.out(), "created org %s (%s) with owner %s\n", sanitize(str(m, "slug")), sanitize(str(m, "id")), sanitize(str(owner, "email")))
	return nil
}

func cmdAdminOrgList(c *ctx) error {
	return listCmd(c, "/admin/orgs", nil, []column{col("ID", "id"), col("SLUG", "slug"), col("DISABLED", "disabled"), col("CREATED_AT", "created_at")})
}

func cmdAdminOrgDisable(c *ctx) error {
	s, err := seg("organization", c.args[0])
	if err != nil {
		return err
	}
	return simpleCmd(c, "POST", joinPath("admin", "orgs", s, "disable"), nil, "disabled org "+c.args[0])
}

var auditCols = []column{
	col("SEQ", "seq"), col("TS", "ts"),
	{header: "ACTOR", get: func(m map[string]any) string {
		if a, ok := m["actor"].(map[string]any); ok {
			return cell(a["type"]) + ":" + cell(a["id"])
		}
		return cell(m["actor"])
	}},
	col("ACTION", "action"), col("TARGET", "target"), col("RESULT", "result"), col("SOURCE_IP", "source_ip"),
}

func cmdAdminAuditList(c *ctx) error {
	q := url.Values{}
	if c.has("limit") {
		q.Set("limit", c.flag("limit"))
	}
	return listCmd(c, "/admin/audit", q, auditCols)
}

func cmdAdminAuditVerify(c *ctx) error { return verifyCmd(c, "/admin/audit/verify") }

func verifyCmd(c *ctx, path string) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("GET", path, nil, nil)
	if err != nil {
		return err
	}
	var v struct {
		Valid           *bool  `json:"valid"`
		FirstInvalidSeq *int64 `json:"first_invalid_seq"`
	}
	if err := resp.decode(&v); err != nil {
		return err
	}
	if v.Valid == nil {
		return genericErr("unexpected response from server")
	}
	if c.json() {
		if err := printRawJSON(c.out(), resp.body); err != nil {
			return err
		}
	} else if *v.Valid {
		fmt.Fprintln(c.out(), "chain valid")
	} else if v.FirstInvalidSeq != nil {
		fmt.Fprintf(c.out(), "chain invalid at seq %d\n", *v.FirstInvalidSeq)
	} else {
		fmt.Fprintln(c.out(), "chain invalid")
	}
	if !*v.Valid {
		return exitSilently(ExitChainInvalid)
	}
	return nil
}

// ---- members & grants ----

func cmdMemberAdd(c *ctx) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	pw, err := c.app.readPassword("Initial password: ")
	if err != nil {
		return err
	}
	resp, err := cl.do("POST", "/members", nil, map[string]string{"email": c.args[0], "role": c.flag("role"), "password": pw})
	if err != nil {
		return err
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	fmt.Fprintf(c.out(), "added %s as %s (%s)\n", sanitize(str(m, "email")), sanitize(str(m, "role")), sanitize(str(m, "id")))
	return nil
}

func cmdMemberList(c *ctx) error {
	return listCmd(c, "/members", nil, []column{
		col("ID", "id"), col("EMAIL", "email"), col("ROLE", "role"),
		{header: "GRANTS", get: func(m map[string]any) string {
			gs, _ := m["grants"].([]any)
			var parts []string
			for _, g := range gs {
				if gm, ok := g.(map[string]any); ok {
					parts = append(parts, str(gm, "project")+":"+str(gm, "level"))
				}
			}
			if len(parts) == 0 {
				return "-"
			}
			return strings.Join(parts, ",")
		}},
		col("CREATED_AT", "created_at"),
	})
}

func memberCall(c *ctx, method string, pathFn func(id string) (string, error), body any, msg string) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	id, err := lookupMember(cl, c.args[0])
	if err != nil {
		return err
	}
	path, err := pathFn(id)
	if err != nil {
		return err
	}
	resp, err := cl.do(method, path, nil, body)
	if err != nil {
		return err
	}
	if c.json() {
		return printJSONOr(c, resp, map[string]string{"status": "ok"})
	}
	fmt.Fprintln(c.out(), sanitize(msg))
	return nil
}

func memberPath(id string, rest ...string) (string, error) {
	s, err := seg("member id", id)
	if err != nil {
		return "", err
	}
	return joinPath(append([]string{"members", s}, rest...)...), nil
}

func cmdMemberRole(c *ctx) error {
	role := c.args[1]
	return memberCall(c, "PATCH", func(id string) (string, error) { return memberPath(id) },
		map[string]string{"role": role}, fmt.Sprintf("%s is now %s", c.args[0], role))
}

func cmdMemberRemove(c *ctx) error {
	return memberCall(c, "DELETE", func(id string) (string, error) { return memberPath(id) },
		nil, "removed "+c.args[0])
}

func cmdGrantSet(c *ctx) error {
	ps, err := seg("project", c.flag("project"))
	if err != nil {
		return err
	}
	return memberCall(c, "PUT", func(id string) (string, error) { return memberPath(id, "grants", ps) },
		map[string]string{"level": c.flag("level")},
		fmt.Sprintf("granted %s %s on %s", c.args[0], c.flag("level"), c.flag("project")))
}

func cmdGrantRevoke(c *ctx) error {
	ps, err := seg("project", c.flag("project"))
	if err != nil {
		return err
	}
	return memberCall(c, "DELETE", func(id string) (string, error) { return memberPath(id, "grants", ps) },
		nil, fmt.Sprintf("revoked %s's grant on %s", c.args[0], c.flag("project")))
}

// ---- projects & environments ----

func cmdProjectCreate(c *ctx) error {
	return simpleCmd(c, "POST", "/projects", map[string]string{"slug": c.args[0]}, "created project "+c.args[0])
}

func cmdProjectList(c *ctx) error {
	return listCmd(c, "/projects", nil, []column{col("ID", "id"), col("SLUG", "slug"), col("LEVEL", "level"), col("CREATED_AT", "created_at")})
}

func cmdEnvCreate(c *ctx) error {
	ps, err := seg("project", c.flag("project"))
	if err != nil {
		return err
	}
	prot := c.flag("protected") == "true"
	msg := "created env " + c.args[0] + " in " + c.flag("project")
	if prot {
		msg += " (protected)"
	}
	return simpleCmd(c, "POST", joinPath("projects", ps, "envs"), map[string]any{"slug": c.args[0], "protected": prot}, msg)
}

func cmdEnvList(c *ctx) error {
	ps, err := seg("project", c.flag("project"))
	if err != nil {
		return err
	}
	return listCmd(c, joinPath("projects", ps, "envs"), nil, []column{col("ID", "id"), col("SLUG", "slug"), col("PROTECTED", "protected"), col("CREATED_AT", "created_at")})
}

// ---- change requests ----

func cmdChangeList(c *ctx) error {
	q := url.Values{}
	if c.has("status") {
		q.Set("status", c.flag("status"))
	}
	return listCmd(c, "/changes", q, []column{
		col("ID", "id"), col("PROJECT", "project"), col("ENV", "env"), col("KEY", "key"), col("OP", "op"),
		col("STATUS", "status"), col("PROPOSED_BY", "proposed_by"), col("CREATED_AT", "created_at"),
		col("DECIDED_BY", "decided_by"), col("APPLIED_VERSION", "applied_version"),
	})
}

func changeDecision(c *ctx, verb, past string) error {
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	s, err := seg("change id", c.args[0])
	if err != nil {
		return err
	}
	resp, err := cl.do("POST", joinPath("changes", s, verb), nil, nil)
	if err != nil {
		return err
	}
	if c.json() {
		return printJSONOr(c, resp, map[string]string{"id": c.args[0], "status": past})
	}
	var m map[string]any
	_ = resp.decode(&m)
	if v := str(m, "version"); v != "" {
		fmt.Fprintf(c.out(), "%s change %s (version %s)\n", past, sanitize(c.args[0]), sanitize(v))
	} else {
		fmt.Fprintf(c.out(), "%s change %s\n", past, sanitize(c.args[0]))
	}
	return nil
}

func cmdChangeApprove(c *ctx) error { return changeDecision(c, "approve", "approved") }
func cmdChangeReject(c *ctx) error  { return changeDecision(c, "reject", "rejected") }

// ---- service tokens ----

func cmdTokenCreate(c *ctx) error {
	ttl, err := parseTTL(c.flag("ttl"))
	if err != nil {
		return err
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	body := map[string]any{"project": c.flag("project"), "env": c.flag("env"), "access": c.flag("access"), "ttl_seconds": ttl}
	if c.has("name") {
		body["name"] = c.flag("name")
	}
	resp, err := cl.do("POST", "/tokens", nil, body)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := resp.decode(&m); err != nil {
		return err
	}
	tok := str(m, "token")
	if !strings.HasPrefix(tok, "cof_st_") || !validTokenChars(tok) {
		return genericErr("unexpected response from server")
	}
	if c.json() {
		return printRawJSON(c.out(), resp.body)
	}
	fmt.Fprintln(c.out(), tok)
	fmt.Fprintf(c.app.Stderr, "id: %s\n", sanitize(str(m, "id")))
	if e := str(m, "expires_at"); e != "" {
		fmt.Fprintf(c.app.Stderr, "expires_at: %s\n", sanitize(e))
	}
	return nil
}

func cmdTokenList(c *ctx) error {
	return listCmd(c, "/tokens", nil, []column{
		col("ID", "id"), col("NAME", "name"), col("PROJECT", "project"), col("ENV", "env"), col("ACCESS", "access"),
		col("CREATED_AT", "created_at"), col("EXPIRES_AT", "expires_at"), col("REVOKED_AT", "revoked_at"),
		col("CREATED_BY", "created_by"), col("LAST_USED_AT", "last_used_at"),
	})
}

func cmdTokenRevoke(c *ctx) error {
	s, err := seg("token id", c.args[0])
	if err != nil {
		return err
	}
	return simpleCmd(c, "DELETE", joinPath("tokens", s), nil, "revoked token "+c.args[0])
}

// ---- org audit ----

func cmdAuditList(c *ctx) error {
	q := url.Values{}
	for _, k := range []string{"actor", "action", "since", "limit"} {
		if c.has(k) {
			q.Set(k, c.flag(k))
		}
	}
	return listCmd(c, "/audit", q, auditCols)
}

func cmdAuditVerify(c *ctx) error { return verifyCmd(c, "/audit/verify") }
