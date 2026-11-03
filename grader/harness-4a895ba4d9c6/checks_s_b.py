"""Coffer grading checks: S13, S14, S15, S16, S17, S18, S19, S20.

Black-box only: the SPEC 7.2 HTTP API through lib.Context helpers. No build
source is read. Every check runs identically for every build.

Interpretations (stricter reading, identical for both builds):
- S13 (destructive, rolled back): attackers writer/reader/viewer/nogrant each
  PATCH their own member record ({role:"owner"} and {role:"admin", org_id:
  <globex id>, is_platform_admin:true}), PUT their own grant on api (and web)
  with level "writer", POST /members with role "owner" + extra fields, and POST
  /tokens with extra fields. admin@acme only PATCHes itself (it may legally
  create members/tokens, so those would be false diffs). Any 4xx = rejected,
  2xx = must be ignored, 5xx = fail. State is snapshotted before and after
  (owner GET /members, /tokens, /changes; root GET /admin/orgs; each
  attacker's GET /me and GET /projects; a fixed set of behavioural access
  probes) with volatile fields dropped. Any difference = fail. A detector
  control (owner PATCHes a scratch member to admin) must show up in the
  snapshot, otherwise the check is error (the snapshot cannot see roles).
- S14: secret routes with T_dev_rw on api/prod and web/dev use same_404
  (must be 404 and identical to an absent env/project). Writes by T_dev_rw on
  api/prod: 404 only. "Any globex path": the API has no org in its paths, so
  the globex targets are globex IDs (owner@globex user id: PATCH member, PUT
  grant) -> 403 or 404 (GRADER overlap rule), plus T_dev_rw reading
  api/dev/CANARY must return the acme value, never the globex one.
  T_dev_r PUT / DELETE / rollback on api/dev -> exactly 403.
- S15: T_prod_rw PUT a junk key on api/prod -> exactly 202 with a change id;
  the value is not readable afterwards (404); the change is then rejected by
  admin@acme as cleanup (non-destructive row).
- S16 (destructive): each of T_dev_r, T_dev_rw, T_prod_rw -> approve, reject,
  GET/POST /members, PATCH member, PUT grant, GET/POST /tokens, DELETE token,
  GET /audit, GET /audit/verify, POST /auth/token -> 401, 403 or 404.
  404 is accepted because SPEC 2.1 ("anything outside a service token's
  project and environment" -> 404) overlaps SPEC 2.7 (403) on these routes,
  and GRADER's overlap rule accepts 403 or 404 there. Every denied approve or
  reject is re-read in GET /changes (the change must still be pending).
  POST /auth/token is sent with the service-token bearer and body {} (a token
  trying to mint a PAT); 400 is NOT accepted.
- S17: revoked scratch tokens (read and read-write) must 401 on the very
  next request after the DELETE returns; a scratch token with a short TTL
  (5 s, or 60 s if the build refuses 5) must 401 at expiry + 1 s; fixture
  T_rev and T_exp (after expires_at + 2 s) -> exactly 401.
- S18: removed scratch user's PAT -> exactly 401; writer->reader lowered grant
  -> next PUT 403; reader->viewer -> next value GET 403; revoked grant -> next
  list 404, then same_404 vs an absent project.
- S19: scratch org (never acme/globex) with owner, member, project and token;
  after root disables it, every PAT and token -> 401 or 403 (a fresh login,
  if it returns a token, must also be refused); acme and globex unaffected.
  The disable path is tried with the org slug, then with its id from
  GET /admin/orgs.
- S20: every SPEC 7.2 route except POST /auth/token, called anonymously,
  -> exactly 401 (destructive-looking routes target absent ids or junk keys).
  /healthz and /readyz -> 200 anonymously. Out-of-surface paths -> exactly 404
  (anonymous and as owner@acme). Malformed / tampered / wrong-prefix bearers
  on GET /api/v1/projects -> exactly 401.
lib.py gaps implemented locally: none needed beyond small JSON helpers here.
"""
from __future__ import annotations

import datetime as _dt
import json as _json
import secrets as _secrets
import time

from registry import Result, check, not_implemented  # noqa: F401

SEC = "/projects/{p}/envs/{e}/secrets"
VOLATILE = {"last_login", "last_login_at", "last_seen", "last_seen_at", "last_used",
            "last_used_at", "updated_at", "request_id"}


def _j(r):
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


def _items(d):
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("items", "members", "tokens", "changes", "data", "results", "orgs",
                  "organizations", "projects", "secrets", "users"):
            if isinstance(d.get(k), list):
                return d[k]
    return None


def _norm(o):
    if isinstance(o, dict):
        return {k: _norm(v) for k, v in sorted(o.items()) if k not in VOLATILE}
    if isinstance(o, list):
        return [_norm(v) for v in o]
    return o


def _canon_list(lst):
    return sorted((_json.dumps(_norm(x), sort_keys=True) for x in (lst or [])))


def _sp(p, e, k=None):
    s = SEC.format(p=p, e=e)
    return s if k is None else f"{s}/{k}"


def _pw():
    return "Pw-" + _secrets.token_urlsafe(18)


def _uid(c, label):
    a = c.actor(label)
    if a.user_id:
        return str(a.user_id)
    d = _j(c.api("GET", "/me", actor=label))
    if isinstance(d, dict):
        u = d.get("user") if isinstance(d.get("user"), dict) else d
        v = u.get("id") or u.get("user_id")
        if v:
            return str(v)
    return None


def _code(r):
    return r.status if r is not None else None


# --------------------------------------------------------------------------------------
# S13
# --------------------------------------------------------------------------------------

ATTACKERS = ("writer@acme", "reader@acme", "viewer@acme", "nogrant@acme")


def _s13_snapshot(c, attackers):
    s = {}
    r = c.api("GET", "/members", actor="owner@acme")
    s["members"] = [r.status, _canon_list(_items(_j(r)))]
    r = c.api("GET", "/tokens", actor="owner@acme")
    s["tokens"] = [r.status, _canon_list(_items(_j(r)))]
    r = c.api("GET", "/changes", actor="owner@acme")
    s["changes"] = [r.status, _canon_list(_items(_j(r)))]
    r = c.api("GET", "/admin/orgs", actor="root")
    s["admin_orgs"] = [r.status, _canon_list(_items(_j(r)))]
    for a in attackers:
        r = c.api("GET", "/me", actor=a)
        s[f"me:{a}"] = [r.status, _json.dumps(_norm(_j(r)), sort_keys=True)]
        r = c.api("GET", "/projects", actor=a)
        s[f"projects:{a}"] = [r.status, _canon_list(_items(_j(r)))]
        s[f"members_route:{a}"] = c.api("GET", "/members", actor=a).status
        s[f"audit_route:{a}"] = c.api("GET", "/audit", actor=a).status
        s[f"tokens_route:{a}"] = c.api("GET", "/tokens", actor=a).status
        s[f"api_dev_list:{a}"] = c.api("GET", _sp("api", "dev"), actor=a).status
        s[f"api_dev_value:{a}"] = c.api("GET", _sp("api", "dev", "CANARY"), actor=a).status
        s[f"web_dev_list:{a}"] = c.api("GET", _sp("web", "dev"), actor=a).status
        s[f"changes_route:{a}"] = c.api("GET", "/changes", actor=a).status
    return s


@check("S13")
def s13(c) -> Result:
    """Self-escalation via PATCH/POST with extra fields rejected or ignored; state re-read"""
    globex_id = ((c.fx.get("orgs") or {}).get("globex") or {}).get("id")
    if not globex_id:
        return c.error("fixture lacks orgs.globex.id")
    uids = {}
    for a in ATTACKERS + ("admin@acme",):
        u = _uid(c, a)
        if not u:
            return c.error(f"no user id for {a}")
        uids[a] = u
    # PATs must work (else every attempt would be a vacuous 401)
    for a in ATTACKERS + ("admin@acme",):
        c.control(lambda a=a: c.api("GET", "/me", actor=a), what=f"{a} GET /me")
    c.control(lambda: c.api("GET", "/members", actor="owner@acme"), what="owner GET /members")
    probe_user = c.scratch_user("acme", "member")

    before = _s13_snapshot(c, ATTACKERS)
    c.log("S13 snapshot keys: %s", sorted(before))

    attempts = []
    for a in ATTACKERS:
        u = uids[a]
        attempts += [
            (a, "PATCH", f"/members/{u}", {"role": "owner"}),
            (a, "PATCH", f"/members/{u}", {"role": "admin", "org_id": globex_id,
                                           "is_platform_admin": True}),
            (a, "PATCH", f"/members/{u}", {"is_platform_admin": True, "org_id": globex_id,
                                           "level": "writer"}),
            (a, "PUT", f"/members/{u}/grants/api", {"level": "writer", "role": "owner",
                                                    "org_id": globex_id}),
            (a, "PUT", f"/members/{u}/grants/web", {"level": "writer"}),
            (a, "POST", "/members", {"email": f"s13-esc-{_secrets.token_hex(4)}@acme.test",
                                     "role": "owner", "password": c.secret("pw:s13-esc", _pw(), "password"),
                                     "org_id": globex_id, "is_platform_admin": True}),
            (a, "POST", "/tokens", {"project": "api", "env": "prod", "access": "read-write",
                                    "ttl_seconds": 600, "name": "s13-esc", "level": "writer",
                                    "role": "owner", "org_id": globex_id, "is_platform_admin": True}),
        ]
    ua = uids["admin@acme"]
    attempts += [
        ("admin@acme", "PATCH", f"/members/{ua}", {"role": "owner"}),
        ("admin@acme", "PATCH", f"/members/{ua}", {"role": "admin", "org_id": globex_id,
                                                   "is_platform_admin": True}),
    ]
    accepted = []
    for (a, m, p, body) in attempts:
        r = c.api(m, p, actor=a, json=body)
        what = f"{a} {m} {p} {sorted(body)}"
        if r.status == 0:
            c.error_once(f"transport error: {what}")
            continue
        if r.status >= 500:
            c.expect(False, f"{what} -> {r.status}")
            continue
        if 200 <= r.status < 300:
            d = _j(r)
            if isinstance(d, dict) and isinstance(d.get("token"), str):
                c.secret("token:s13-escape", d["token"], "token")
            accepted.append(f"{what}->{r.status}")
            c.log("S13 accepted (must be ignored): %s -> %s", what, r.status)
        else:
            c.log("S13 rejected: %s -> %s", what, r.status)

    after = _s13_snapshot(c, ATTACKERS)
    changed = [k for k in before if _json.dumps(before[k], sort_keys=True) != _json.dumps(after.get(k), sort_keys=True)]
    for k in changed:
        c.log("S13 DIFF %s\n before=%s\n after=%s", k, _json.dumps(before[k])[:1500], _json.dumps(after.get(k))[:1500])
        c.expect(False, f"state changed after self-escalation attempts: {k} (before {str(before[k])[:60]} after {str(after.get(k))[:60]})")
    if not changed:
        c.expect(True, f"state identical after {len(attempts)} attempts ({len(accepted)} returned 2xx)")

    # detector control: a real role change must be visible in the members snapshot
    if c.control(lambda: c.api("PATCH", f"/members/{probe_user.user_id}", actor="owner@acme",
                               json={"role": "admin"}), what="owner PATCH scratch member -> admin"):
        r = c.api("GET", "/members", actor="owner@acme")
        if _canon_list(_items(_j(r))) == after["members"][1]:
            c.error_once("members snapshot did not reflect a real role change; cannot judge S13")
    return c.done(f"{len(attempts)} self-escalation attempts, state unchanged; 2xx-ignored: {len(accepted)}",
                  data={"accepted_2xx": accepted[:20], "changed": changed})


# --------------------------------------------------------------------------------------
# S14
# --------------------------------------------------------------------------------------

@check("S14")
def s14(c) -> Result:
    """T_dev_rw -> api/prod, web, globex -> 404; T_dev_r writes 403"""
    can = c.fx.get("canaries") or {}
    acme_dev = can.get("acme/api/dev/CANARY")
    globex_dev = can.get("globex/api/dev/CANARY")
    if not acme_dev or not globex_dev:
        return c.error("fixture canaries missing")
    rw, ro, prw = "T_dev_rw", "T_dev_r", "T_prod_rw"
    absent_env = c.absent_slug()
    absent_proj = c.absent_slug()

    # T_dev_rw on api/prod (other env of same project)
    c.same_404(lambda: c.api("GET", _sp("api", "prod"), actor=rw),
               lambda: c.api("GET", _sp("api", absent_env), actor=rw),
               lambda: c.api("GET", _sp("api", "prod"), actor=prw),
               what="T_dev_rw GET api/prod list")
    c.same_404(lambda: c.api("GET", _sp("api", "prod", "CANARY"), actor=rw),
               lambda: c.api("GET", _sp("api", absent_env, "CANARY"), actor=rw),
               lambda: c.api("GET", _sp("api", "prod", "CANARY"), actor=prw),
               what="T_dev_rw GET api/prod/CANARY")
    c.same_404(lambda: c.api("GET", f"/projects/api/envs/prod/export", actor=rw, query={"format": "json"}),
               lambda: c.api("GET", f"/projects/api/envs/{absent_env}/export", actor=rw, query={"format": "json"}),
               lambda: c.api("GET", f"/projects/api/envs/prod/export", actor=prw, query={"format": "json"}),
               what="T_dev_rw export api/prod")
    k1 = c.junk_key()
    c.denied(lambda: c.api("PUT", _sp("api", "prod", k1), actor=rw, json={"value": "s14"}),
             lambda: c.api("PUT", _sp("api", "dev", k1), actor=rw, json={"value": "s14"}),
             allow=(404,), what="T_dev_rw PUT api/prod junk")
    c.denied(lambda: c.api("DELETE", _sp("api", "prod", "CANARY"), actor=rw),
             lambda: c.api("GET", _sp("api", "dev", k1), actor=rw),
             allow=(404,), what="T_dev_rw DELETE api/prod/CANARY")
    # web project
    c.same_404(lambda: c.api("GET", _sp("web", "dev"), actor=rw),
               lambda: c.api("GET", _sp(absent_proj, "dev"), actor=rw),
               lambda: c.api("GET", _sp("web", "dev"), actor="owner@acme"),
               what="T_dev_rw GET web/dev list")
    c.same_404(lambda: c.api("GET", _sp("web", "dev", "CANARY"), actor=rw),
               lambda: c.api("GET", _sp(absent_proj, "dev", "CANARY"), actor=rw),
               lambda: c.api("GET", _sp("web", "dev", "CANARY"), actor="owner@acme"),
               what="T_dev_rw GET web/dev/CANARY")
    c.denied(lambda: c.api("PUT", _sp("web", "dev", k1), actor=rw, json={"value": "s14"}),
             lambda: c.api("PUT", _sp("api", "dev", k1), actor=rw, json={"value": "s14b"}),
             allow=(404,), what="T_dev_rw PUT web/dev junk")
    # globex: colliding slug resolves in acme only; globex ids invisible
    r = c.api("GET", _sp("api", "dev", "CANARY"), actor=rw)
    d = _j(r) if r.status == 200 else None
    val = d.get("value") if isinstance(d, dict) else None
    c.expect(r.status == 200 and val == acme_dev,
             f"T_dev_rw GET api/dev/CANARY -> {r.status}, acme value={val == acme_dev}")
    c.expect(val != globex_dev, "T_dev_rw GET api/dev/CANARY returned the globex canary")
    gid = _uid(c, "owner@globex")
    if not gid:
        c.error_once("no user id for owner@globex")
    else:
        c.denied(lambda: c.api("PATCH", f"/members/{gid}", actor=rw, json={"role": "owner"}),
                 lambda: c.api("GET", "/members", actor="owner@globex"),
                 allow=(403, 404), what="T_dev_rw PATCH globex owner")
        c.denied(lambda: c.api("PUT", f"/members/{gid}/grants/api", actor=rw, json={"level": "viewer"}),
                 lambda: c.api("GET", "/members", actor="owner@globex"),
                 allow=(403, 404), what="T_dev_rw PUT grant globex owner")
    # T_dev_r writes -> 403
    k2, k3 = c.junk_key(), c.junk_key()
    c.denied(lambda: c.api("PUT", _sp("api", "dev", k2), actor=ro, json={"value": "x"}),
             lambda: c.api("PUT", _sp("api", "dev", k2), actor=rw, json={"value": "v1"}),
             allow=(403,), what="T_dev_r PUT api/dev junk")
    c.denied(lambda: c.api("POST", _sp("api", "dev", k2) + "/rollback", actor=ro, json={"to": 1}),
             lambda: c.api("PUT", _sp("api", "dev", k2), actor=rw, json={"value": "v2"}),
             allow=(403,), what="T_dev_r rollback api/dev junk")
    c.denied(lambda: c.api("POST", _sp("api", "dev", k2) + "/rollback", actor=ro, json={"to": 1}),
             lambda: c.api("POST", _sp("api", "dev", k2) + "/rollback", actor=rw, json={"to": 1}),
             allow=(403,), what="T_dev_r rollback (after rw rollback)")
    c.api("PUT", _sp("api", "dev", k3), actor=rw, json={"value": "del"})
    c.denied(lambda: c.api("DELETE", _sp("api", "dev", k2), actor=ro),
             lambda: c.api("DELETE", _sp("api", "dev", k3), actor=rw),
             allow=(403,), what="T_dev_r DELETE api/dev junk")
    r = c.api("GET", _sp("api", "dev", k2), actor=rw)
    c.expect(r.status == 200, f"junk key {k2} still present after T_dev_r DELETE -> {r.status}")
    return c.done("T_dev_rw out-of-scope 404 (identical to absent); T_dev_r writes 403")


# --------------------------------------------------------------------------------------
# S15
# --------------------------------------------------------------------------------------

@check("S15")
def s15(c) -> Result:
    """T_prod_rw set -> 202 (a token cannot skip approval)"""
    tok = "T_prod_rw"
    c.control(lambda: c.api("GET", _sp("api", "prod"), actor=tok), what="T_prod_rw GET api/prod list")
    k = c.junk_key()
    v = c.secret("canary:s15", _secrets.token_urlsafe(30), "canary")
    r = c.api("PUT", _sp("api", "prod", k), actor=tok, json={"value": v})
    d = _j(r)
    cid = d.get("change_id") if isinstance(d, dict) else None
    c.expect(r.status == 202, f"T_prod_rw PUT api/prod/{k} -> {r.status} (want 202)")
    c.expect(r.status != 202 or bool(cid), "202 without change_id")
    g = c.api("GET", _sp("api", "prod", k), actor="owner@acme")
    c.expect(g.status == 404, f"value applied without approval: owner GET api/prod/{k} -> {g.status} (want 404)")
    if cid:
        lr = c.api("GET", "/changes", actor="owner@acme")
        ids = [str(x.get("id")) for x in (_items(_j(lr)) or []) if isinstance(x, dict)]
        c.expect(str(cid) in ids, f"change {cid} not listed in GET /changes ({lr.status})")
        rj = c.api("POST", f"/changes/{cid}/reject", actor="admin@acme")
        c.log("S15 cleanup reject %s -> %s", cid, rj.status)
    return c.done(f"T_prod_rw protected write -> 202 change_id, value not applied")


# --------------------------------------------------------------------------------------
# S16
# --------------------------------------------------------------------------------------

@check("S16")
def s16(c) -> Result:
    """Service tokens -> approve, members, POST /tokens, audit, /auth/token -> 403/401"""
    viewer = _uid(c, "viewer@acme")
    if not viewer:
        return c.error("no user id for viewer@acme")
    scratch = c.scratch_user("acme", "member")
    allow = (401, 403, 404)

    def new_cr():
        k = c.junk_key()
        r = c.api("PUT", _sp("api", "prod", k), actor="writer@acme", json={"value": "s16-" + k})
        d = _j(r)
        cid = d.get("change_id") if isinstance(d, dict) else None
        if r.status != 202 or not cid:
            c.error_once(f"could not create change request: writer PUT api/prod -> {r.status}")
            return None
        return str(cid)

    roles = ["member", "admin"]
    levels = ["viewer", "reader"]
    for i, t in enumerate(("T_dev_r", "T_dev_rw", "T_prod_rw")):
        # each control is a real change (alternating), so a 409-on-no-op cannot fake an error
        role_ctl, role_probe = roles[(i + 1) % 2], "owner"
        lvl_ctl = levels[i % 2]
        c.control(lambda t=t: c.api("GET", _sp("api", "prod" if t == "T_prod_rw" else "dev"), actor=t),
                  what=f"{t} works in scope")
        for verb in ("approve", "reject"):
            cp, cc = new_cr(), new_cr()
            if not cp or not cc:
                continue
            c.denied(lambda: c.api("POST", f"/changes/{cp}/{verb}", actor=t),
                     lambda: c.api("POST", f"/changes/{cc}/{verb}", actor="admin@acme"),
                     allow=allow, what=f"{t} {verb} change")
            lr = c.api("GET", "/changes", actor="owner@acme")
            st = {str(x.get("id")): str(x.get("status")) for x in (_items(_j(lr)) or []) if isinstance(x, dict)}
            c.expect(st.get(cp, "").lower() in ("pending", "open", "proposed"),
                     f"{t} {verb}: change {cp} status {st.get(cp)!r} after denied {verb} (want pending)")
        c.denied(lambda: c.api("GET", "/members", actor=t),
                 lambda: c.api("GET", "/members", actor="owner@acme"), allow=allow, what=f"{t} GET /members")

        def mk_member(actor):
            return lambda: c.api("POST", "/members", actor=actor, json={
                "email": f"s16-{_secrets.token_hex(4)}@acme.test", "role": "member",
                "password": c.secret("pw:s16-m", _pw(), "password")})
        c.denied(mk_member(t), mk_member("owner@acme"), allow=allow, what=f"{t} POST /members")
        c.denied(lambda: c.api("PATCH", f"/members/{scratch.user_id}", actor=t, json={"role": role_probe}),
                 lambda: c.api("PATCH", f"/members/{scratch.user_id}", actor="owner@acme", json={"role": role_ctl}),
                 allow=allow, what=f"{t} PATCH member")
        c.denied(lambda: c.api("PUT", f"/members/{scratch.user_id}/grants/api", actor=t, json={"level": "writer"}),
                 lambda: c.api("PUT", f"/members/{scratch.user_id}/grants/api", actor="owner@acme", json={"level": lvl_ctl}),
                 allow=allow, what=f"{t} PUT grant")
        c.denied(lambda: c.api("GET", "/tokens", actor=t),
                 lambda: c.api("GET", "/tokens", actor="owner@acme"), allow=allow, what=f"{t} GET /tokens")

        def mk_tok(actor):
            def f():
                r = c.api("POST", "/tokens", actor=actor, json={"project": "api", "env": "dev",
                                                                "access": "read", "ttl_seconds": 600,
                                                                "name": "s16"})
                d = _j(r)
                if isinstance(d, dict) and isinstance(d.get("token"), str):
                    c.secret("token:s16", d["token"], "token")
                return r
            return f
        c.denied(mk_tok(t), mk_tok("owner@acme"), allow=allow, what=f"{t} POST /tokens")
        victim = c.scratch_token("api", "dev", "read", 600)
        other = c.scratch_token("api", "dev", "read", 600)
        c.denied(lambda: c.api("DELETE", f"/tokens/{victim.token_id}", actor=t),
                 lambda: c.api("DELETE", f"/tokens/{other.token_id}", actor="owner@acme"),
                 allow=allow, what=f"{t} DELETE /tokens/id")
        c.denied(lambda: c.api("GET", "/audit", actor=t),
                 lambda: c.api("GET", "/audit", actor="admin@acme"), allow=allow, what=f"{t} GET /audit")
        c.denied(lambda: c.api("GET", "/audit/verify", actor=t),
                 lambda: c.api("GET", "/audit/verify", actor="admin@acme"), allow=allow, what=f"{t} GET /audit/verify")

        def login_ctl():
            r = c.api("POST", "/auth/token", json={"email": scratch.email, "password": scratch.password})
            d = _j(r)
            if isinstance(d, dict) and isinstance(d.get("token"), str):
                c.secret("pat:s16-ctl", d["token"], "token")
            return r

        # r2 fix (S16 on build-2): probe and control differ ONLY in the bearer. Probe =
        # the same valid {email,password} body as the control + Authorization: Bearer <st>.
        # 401/403/404 = pass. 200 with a PAT = the route ignored the bearer (SPEC makes
        # /auth/token unauthenticated), which does not show the token minted anything:
        # recorded as error (review), never as a pass or a blocker fail.
        probe_pat = {}

        def login_probe():
            r = c.api("POST", "/auth/token", actor=t, json={"email": scratch.email, "password": scratch.password})
            d = _j(r)
            if isinstance(d, dict) and isinstance(d.get("token"), str):
                c.secret("pat:s16-probe", d["token"], "token")
                probe_pat["issued"] = r.status
            return r
        cr = login_ctl()
        if not (200 <= cr.status < 300):
            c.error_once(f"control failed: {t} POST /auth/token valid creds, no bearer ({cr.status})")
            continue
        c.controls += 1
        c.log("CONTROL ok: valid login without bearer (%s)", cr.status)
        pr = login_probe()
        c.log("S16 %s /auth/token with bearer: status=%s pat_issued=%s", t, pr.status, bool(probe_pat))
        if pr.status >= 500:
            c.saw_5xx.append(f"denied-probe {t} POST /auth/token -> {pr.status}")
            c.expect(False, f"{t} POST /auth/token (bearer + valid creds) -> {pr.status} (5xx)")
        elif pr.status in allow:
            c.expect(True, f"{t} POST /auth/token (bearer + valid creds): denied {pr.status}, no PAT")
        elif 200 <= pr.status < 300 and probe_pat:
            c.error_once(f"{t} POST /auth/token with service-token bearer + valid creds -> {pr.status} "
                         f"and a PAT: route ignores the bearer (unauthenticated by SPEC); review, not graded")
        else:
            c.expect(False, f"{t} POST /auth/token (bearer + valid creds) -> {pr.status} (want 401/403/404)")
    return c.done("service tokens refused approve/reject/members/grants/tokens/audit/auth-token")


# --------------------------------------------------------------------------------------
# S17
# --------------------------------------------------------------------------------------

def _parse_ts(s):
    try:
        t = _dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)
    except (TypeError, ValueError):
        return None


@check("S17")
def s17(c) -> Result:
    """Revoked and expired tokens -> 401 on the next request (<= 1 s)"""
    timings = {}
    # 1. revoke a scratch read token and a scratch read-write token
    for access in ("read", "read-write"):
        tk = c.scratch_token("api", "dev", access, 3600)
        if not tk.token_id:
            c.error_once(f"scratch {access} token has no id")
            continue
        k = c.junk_key()
        if not c.control(lambda: c.api("GET", _sp("api", "dev"), actor=tk), what=f"{access} token works before revoke"):
            continue
        rv = c.api("DELETE", f"/tokens/{tk.token_id}", actor="owner@acme")
        t0 = time.monotonic()
        if not (200 <= rv.status < 300):
            c.error_once(f"owner DELETE /tokens/{{id}} -> {rv.status}")
            continue
        if access == "read":
            r = c.api("GET", _sp("api", "dev"), actor=tk)
        else:
            r = c.api("PUT", _sp("api", "dev", k), actor=tk, json={"value": "after-revoke"})
        dt = (time.monotonic() - t0) * 1000
        timings[f"revoked_{access}_ms"] = round(dt)
        c.expect(r.status == 401, f"revoked {access} token next request -> {r.status} (want 401) after {dt:.0f} ms")
        c.expect(dt <= 1000, f"revoked {access} token: first post-revoke probe completed {dt:.0f} ms after DELETE (want <= 1000)")
        if access == "read-write":
            g = c.api("GET", _sp("api", "dev", k), actor="owner@acme")
            c.expect(g.status == 404, f"write by revoked token applied: GET {k} -> {g.status}")
        r2 = c.api("GET", _sp("api", "dev", "CANARY"), actor=tk)
        c.expect(r2.status == 401, f"revoked {access} token GET value -> {r2.status} (want 401)")
    # 2. fixture T_rev
    if not (c.fx.get("tokens") or {}).get("T_rev", {}).get("token"):
        c.error_once("fixture T_rev missing")
    else:
        c.denied(lambda: c.api("GET", _sp("api", "dev"), actor="T_rev"),
                 lambda: c.api("GET", _sp("api", "dev"), actor="T_dev_r"),
                 allow=(401,), what="T_rev (revoked) GET api/dev list")
    # 3. short-TTL scratch token expiring under observation
    t_created = None
    ttl_used = None
    exp_tok = None
    for ttl in (5, 60):
        n = f"s17exp{ttl}"
        r = c.api("POST", "/tokens", actor="owner@acme",
                  json={"project": "api", "env": "dev", "access": "read", "ttl_seconds": ttl, "name": n})
        t_created = time.monotonic()
        d = _j(r)
        if r.status in (200, 201) and isinstance(d, dict) and isinstance(d.get("token"), str):
            c.secret(f"token:{n}", d["token"], "token")
            exp_tok, ttl_used = d["token"], ttl
            srv_exp = _parse_ts(d.get("expires_at"))
            if srv_exp is not None:
                drift = (srv_exp - c.now()).total_seconds() - ttl
                c.log("S17 ttl=%s server expires_at=%s drift=%.1fs", ttl, d.get("expires_at"), drift)
                timings[f"ttl{ttl}_expires_at_drift_s"] = round(drift, 2)
            break
        c.log("S17 POST /tokens ttl=%s -> %s", ttl, r.status)
    if not exp_tok:
        c.error_once("could not create a short-TTL token (ttl 5 and 60 refused)")
    else:
        hdr = {"Authorization": f"Bearer {exp_tok}"}
        c.control(lambda: c.api("GET", _sp("api", "dev"), headers=hdr), what=f"ttl={ttl_used}s token works before expiry")
        wake = t_created + ttl_used + 1.0
        while time.monotonic() < wake:
            time.sleep(min(0.2, max(0.0, wake - time.monotonic())))
        r = c.api("GET", _sp("api", "dev"), headers=hdr)
        timings["short_ttl_s"] = ttl_used
        c.expect(r.status == 401, f"ttl={ttl_used}s token at expiry+1 s -> {r.status} (want 401)")
    # 4. fixture T_exp
    te = (c.fx.get("tokens") or {}).get("T_exp") or {}
    exp = _parse_ts(te.get("expires_at"))
    if not te.get("token") or not exp:
        c.error_once("fixture T_exp or its expires_at missing")
    else:
        wait = (exp - c.now()).total_seconds() + 2.0
        if wait > 120:
            c.error_once(f"T_exp expires too far in the future ({wait:.0f} s)")
        else:
            if wait > 0:
                time.sleep(wait)
            c.denied(lambda: c.api("GET", _sp("api", "dev"), actor="T_exp"),
                     lambda: c.api("GET", _sp("api", "dev"), actor="T_dev_r"),
                     allow=(401,), what="T_exp (expired) GET api/dev list")
    return c.done("revoked and expired tokens -> 401 on the next request", data=timings)


# --------------------------------------------------------------------------------------
# S18
# --------------------------------------------------------------------------------------

@check("S18")
def s18(c) -> Result:
    """Removed user's PAT 401; lowered grant next request; revoked grant 404"""
    timings = {}
    # removed user
    u1 = c.scratch_user("acme", "member", grants={"api": "reader"})
    if c.control(lambda: c.api("GET", _sp("api", "dev"), actor=u1), what="scratch reader lists api/dev before removal"):
        rm = c.api("DELETE", f"/members/{u1.user_id}", actor="owner@acme")
        t0 = time.monotonic()
        if not (200 <= rm.status < 300):
            c.error_once(f"owner DELETE /members/{{id}} -> {rm.status}")
        else:
            r = c.api("GET", _sp("api", "dev"), actor=u1)
            timings["removed_ms"] = round((time.monotonic() - t0) * 1000)
            c.expect(r.status == 401, f"removed user's PAT next request -> {r.status} (want 401)")
            r = c.api("GET", "/me", actor=u1)
            c.expect(r.status == 401, f"removed user's PAT GET /me -> {r.status} (want 401)")
    # lowered grant
    u2 = c.scratch_user("acme", "member", grants={"api": "writer"})
    k = c.junk_key()
    gpath = f"/members/{u2.user_id}/grants/api"
    if c.control(lambda: c.api("PUT", _sp("api", "dev", k), actor=u2, json={"value": "w1"}),
                 what="scratch writer PUT api/dev junk"):
        g = c.api("PUT", gpath, actor="owner@acme", json={"level": "reader"})
        t0 = time.monotonic()
        if not (200 <= g.status < 300):
            c.error_once(f"lower grant writer->reader -> {g.status}")
        else:
            r = c.api("PUT", _sp("api", "dev", k), actor=u2, json={"value": "w2"})
            timings["lowered_reader_ms"] = round((time.monotonic() - t0) * 1000)
            c.expect(r.status == 403, f"writer lowered to reader: next PUT -> {r.status} (want 403)")
            c.control(lambda: c.api("GET", _sp("api", "dev", k), actor=u2), what="reader still reads value")
            g = c.api("PUT", gpath, actor="owner@acme", json={"level": "viewer"})
            t0 = time.monotonic()
            if not (200 <= g.status < 300):
                c.error_once(f"lower grant reader->viewer -> {g.status}")
            else:
                r = c.api("GET", _sp("api", "dev", k), actor=u2)
                timings["lowered_viewer_ms"] = round((time.monotonic() - t0) * 1000)
                c.expect(r.status == 403, f"reader lowered to viewer: next value GET -> {r.status} (want 403)")
                c.control(lambda: c.api("GET", _sp("api", "dev"), actor=u2), what="viewer still lists")
                # revoked grant
                g = c.api("DELETE", gpath, actor="owner@acme")
                t0 = time.monotonic()
                if not (200 <= g.status < 300):
                    c.error_once(f"revoke grant -> {g.status}")
                else:
                    r = c.api("GET", _sp("api", "dev"), actor=u2)
                    timings["revoked_grant_ms"] = round((time.monotonic() - t0) * 1000)
                    c.expect(r.status == 404, f"revoked grant: next list -> {r.status} (want 404)")
                    ab = c.absent_slug()
                    c.same_404(lambda: c.api("GET", _sp("api", "dev"), actor=u2),
                               lambda: c.api("GET", _sp(ab, "dev"), actor=u2),
                               lambda: c.api("GET", _sp("api", "dev"), actor="owner@acme"),
                               what="revoked-grant list vs absent project")
    for kname, ms in timings.items():
        c.expect(ms <= 1000, f"{kname}: probe completed {ms} ms after the change (want <= 1000)")
    return c.done("removed PAT 401; lowered grant 403 next request; revoked grant 404", data=timings)


# --------------------------------------------------------------------------------------
# S19
# --------------------------------------------------------------------------------------

@check("S19")
def s19(c) -> Result:
    """Disabled org: PATs and tokens 401/403; other org unaffected"""
    slug, owner = c.scratch_org()
    proj = c.scratch_project(actor=owner)
    mem = c.scratch_user(slug, "member", grants={proj: "reader"})
    tok = c.scratch_token(proj, "dev", "read", 3600, actor=owner, org=slug)
    val = c.secret("canary:s19", _secrets.token_urlsafe(30), "canary")
    pr = c.api("PUT", _sp(proj, "dev", "S19_K"), actor=owner, json={"value": val})
    if pr.status not in (200, 201):
        return c.error(f"scratch org owner PUT secret -> {pr.status}")
    acme_can = (c.fx.get("canaries") or {}).get("acme/api/dev/CANARY")
    pre = [
        ("owner GET /members", lambda: c.api("GET", "/members", actor=owner)),
        ("owner GET /projects", lambda: c.api("GET", "/projects", actor=owner)),
        ("owner GET value", lambda: c.api("GET", _sp(proj, "dev", "S19_K"), actor=owner)),
        ("member GET value", lambda: c.api("GET", _sp(proj, "dev", "S19_K"), actor=mem)),
        ("member GET /me", lambda: c.api("GET", "/me", actor=mem)),
        ("token GET value", lambda: c.api("GET", _sp(proj, "dev", "S19_K"), actor=tok)),
        ("token GET list", lambda: c.api("GET", _sp(proj, "dev"), actor=tok)),
    ]
    for what, f in pre:
        c.control(f, what=f"before disable: {what}")
    # disable (slug, then id)
    rd = c.api("POST", f"/admin/orgs/{slug}/disable", actor="root")
    if not (200 <= rd.status < 300):
        oid = None
        for o in _items(_j(c.api("GET", "/admin/orgs", actor="root"))) or []:
            if isinstance(o, dict) and o.get("slug") == slug:
                oid = o.get("id")
        if oid:
            rd = c.api("POST", f"/admin/orgs/{oid}/disable", actor="root")
    t0 = time.monotonic()
    if not (200 <= rd.status < 300):
        return c.error(f"root disable scratch org -> {rd.status}")
    first = c.api("GET", _sp(proj, "dev", "S19_K"), actor=tok)
    ms = round((time.monotonic() - t0) * 1000)
    c.expect(first.status in (401, 403), f"disabled org token next request -> {first.status} (want 401/403)")
    c.expect(ms <= 1000, f"first post-disable probe took {ms} ms (want <= 1000)")
    post = pre + [
        ("owner PUT secret", lambda: c.api("PUT", _sp(proj, "dev", "S19_K"), actor=owner, json={"value": "x"})),
        ("owner POST /tokens", lambda: c.api("POST", "/tokens", actor=owner, json={
            "project": proj, "env": "dev", "access": "read", "ttl_seconds": 600, "name": "s19"})),
        ("token export", lambda: c.api("GET", f"/projects/{proj}/envs/dev/export", actor=tok, query={"format": "json"})),
    ]
    for what, f in post:
        r = f()
        if what == "owner POST /tokens":
            d = _j(r)
            if isinstance(d, dict) and isinstance(d.get("token"), str):
                c.secret("token:s19-post", d["token"], "token")
        c.expect(r.status in (401, 403), f"after disable: {what} -> {r.status} (want 401/403)")
    # a fresh login, if it yields a PAT, must be refused too
    lr = c.api("POST", "/auth/token", json={"email": owner.email, "password": owner.password})
    c.log("S19 login after disable -> %s", lr.status)
    d = _j(lr)
    if 200 <= lr.status < 300 and isinstance(d, dict) and isinstance(d.get("token"), str):
        newpat = c.secret("pat:s19-post-disable", d["token"], "token")
        r = c.api("GET", "/projects", headers={"Authorization": f"Bearer {newpat}"})
        c.expect(r.status in (401, 403), f"PAT issued after disable GET /projects -> {r.status} (want 401/403)")
    elif lr.status >= 500:
        c.expect(False, f"login after disable -> {lr.status}")
    # other orgs unaffected
    r = c.api("GET", _sp("api", "dev", "CANARY"), actor="owner@acme")
    d = _j(r)
    c.expect(r.status == 200 and isinstance(d, dict) and d.get("value") == acme_can,
             f"acme owner GET api/dev/CANARY after disable -> {r.status}")
    for what, f in [("acme T_dev_r list", lambda: c.api("GET", _sp("api", "dev"), actor="T_dev_r")),
                    ("acme writer list", lambda: c.api("GET", _sp("api", "dev"), actor="writer@acme")),
                    ("globex owner GET /projects", lambda: c.api("GET", "/projects", actor="owner@globex")),
                    ("globex owner list api/dev", lambda: c.api("GET", _sp("api", "dev"), actor="owner@globex"))]:
        r = f()
        c.expect(r.status == 200, f"after disable: {what} -> {r.status} (want 200)")
    return c.done(f"disabled org refused {len(post)} PAT/token requests; acme/globex unaffected", data={"first_ms": ms})


# --------------------------------------------------------------------------------------
# S20
# --------------------------------------------------------------------------------------

OUTSIDE = ("/", "/api", "/api/", "/api/v1x/projects", "/api/v2/projects", "/v1/projects",
           "/api/projects", "/projects", "/admin", "/admin/orgs", "/metrics", "/debug/pprof/",
           "/debug/vars", "/swagger", "/swagger/index.html", "/docs", "/openapi.json",
           "/static/app.js", "/.env", "/.git/config", "/favicon.ico", "/index.html",
           "/robots.txt", "/graphql", "/actuator/health", "/server-status", "/healthz/x",
           "/readyz/x", "/auth/token", "/me")


@check("S20")
def s20(c) -> Result:
    """Only health + /auth/token unauthenticated; other paths 404; bad bearers 401"""
    owner = c.actor("owner@acme")
    pat = owner.secret
    st = (c.fx.get("tokens") or {}).get("T_dev_r", {}).get("token")
    if not pat or not st:
        return c.error("fixture owner PAT or T_dev_r token missing")
    for p in ("/healthz", "/readyz"):
        c.control(lambda p=p: c.http("GET", p), what=f"anon GET {p}")
    # /auth/token reachable unauthenticated (control: valid scratch login)
    sc = c.scratch_user("acme", "member")

    def good_login():
        r = c.api("POST", "/auth/token", json={"email": sc.email, "password": sc.password})
        d = _j(r)
        if isinstance(d, dict) and isinstance(d.get("token"), str):
            c.secret("pat:s20-login", d["token"], "token")
        return r
    c.control(good_login, what="anon POST /auth/token valid creds")
    r = c.api("POST", "/auth/token", json={"email": sc.email, "password": "wrong-" + _pw()})
    c.expect(r.status == 401, f"anon POST /auth/token wrong password -> {r.status} (want 401)")

    aid, ab, k = c.absent_id(), c.absent_slug(), c.junk_key()
    vid = _uid(c, "viewer@acme") or aid
    routes = [
        ("POST", "/auth/logout", None), ("POST", "/auth/password", {"current_password": "x" * 12, "new_password": "y" * 14}),
        ("GET", "/me", None),
        ("GET", "/admin/orgs", None), ("POST", "/admin/orgs", {"slug": ab, "owner_email": f"{ab}@x.test", "owner_password": _pw()}),
        ("POST", f"/admin/orgs/{ab}/disable", None), ("GET", "/admin/audit", None), ("GET", "/admin/audit/verify", None),
        ("GET", "/members", None), ("POST", "/members", {"email": f"{ab}@acme.test", "role": "member", "password": _pw()}),
        ("PATCH", f"/members/{aid}", {"role": "owner"}), ("DELETE", f"/members/{aid}", None),
        ("PUT", f"/members/{aid}/grants/api", {"level": "writer"}), ("DELETE", f"/members/{aid}/grants/api", None),
        ("PATCH", f"/members/{vid}", {"role": "owner"}),
        ("GET", "/projects", None), ("POST", "/projects", {"slug": ab}),
        ("GET", "/projects/api/envs", None), ("POST", "/projects/api/envs", {"slug": ab, "protected": False}),
        ("GET", _sp("api", "dev"), None), ("GET", _sp("api", "dev", "CANARY"), None),
        ("PUT", _sp("api", "dev", k), {"value": "anon"}), ("DELETE", _sp("api", "dev", k), None),
        ("GET", _sp("api", "dev", "CANARY") + "/versions", None), ("GET", _sp("api", "dev", "CANARY") + "/versions/1", None),
        ("POST", _sp("api", "dev", k) + "/rollback", {"to": 1}),
        ("GET", "/projects/api/envs/dev/export", None),
        ("GET", "/changes", None), ("POST", f"/changes/{aid}/approve", None), ("POST", f"/changes/{aid}/reject", None),
        ("GET", "/tokens", None), ("POST", "/tokens", {"project": "api", "env": "dev", "access": "read", "ttl_seconds": 60}),
        ("DELETE", f"/tokens/{aid}", None), ("GET", "/audit", None), ("GET", "/audit/verify", None),
    ]
    c.denied(lambda: c.api("GET", "/projects"), lambda: c.api("GET", "/projects", actor=owner),
             allow=(401,), what="anon GET /api/v1/projects")
    for m, p, body in routes:
        kw = {"json": body} if body is not None else {}
        r = c.api(m, p, **kw)
        if r.status == 0:
            c.error_once(f"transport error anon {m} {p}")
            continue
        c.expect(r.status == 401, f"anon {m} /api/v1{p} -> {r.status} (want 401)")
    # out-of-surface paths
    for p in OUTSIDE:
        for who in ("anon", "owner@acme"):
            r = c.http("GET", p, actor=who)
            c.expect(r.status == 404, f"{who} GET {p} -> {r.status} (want 404)")
    r = c.http("POST", "/api/v2/auth/token", json={"email": sc.email, "password": sc.password})
    c.expect(r.status == 404, f"anon POST /api/v2/auth/token -> {r.status} (want 404)")
    # malformed / tampered / wrong-prefix bearers
    flip = pat[:-1] + ("A" if pat[-1] != "A" else "B")
    body = pat.split("_", 2)[-1] if pat.count("_") >= 2 else pat[8:]
    sbody = st.split("_", 2)[-1] if st.count("_") >= 2 else st[7:]
    bad = {
        "empty Bearer": "Bearer ",
        "scheme only": "Bearer",
        "no scheme": pat,
        "Basic": "Basic dXNlcjpwYXNzd29yZA==",
        "Token scheme": f"Token {pat}",
        "flipped last char": f"Bearer {flip}",
        "truncated": f"Bearer {pat[:-4]}",
        "extended": f"Bearer {pat}x",
        "trailing garbage": f"Bearer {pat} extra",
        "pat body as cof_st_": f"Bearer cof_st_{body}",
        "st body as cof_pat_": f"Bearer cof_pat_{sbody}",
        "wrong prefix cof_xx_": f"Bearer cof_xx_{body}",
        "no prefix": f"Bearer {body}",
        "prefix only pat": "Bearer cof_pat_",
        "prefix only st": "Bearer cof_st_",
        "random pat": f"Bearer cof_pat_{_secrets.token_urlsafe(32)}",
        "random st": f"Bearer cof_st_{_secrets.token_urlsafe(32)}",
        "long": "Bearer cof_pat_" + "A" * 4000,
        "non-ascii": "Bearer cof_pat_" + "é" * 20,
        "sql-ish": "Bearer cof_pat_' OR '1'='1",
        "jwt-like": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        "flipped st": f"Bearer {st[:-1] + ('A' if st[-1] != 'A' else 'B')}",
    }
    for name, hv in bad.items():
        c.denied(lambda hv=hv: c.api("GET", "/projects", headers={"Authorization": hv}),
                 lambda: c.api("GET", "/projects", headers={"Authorization": f"Bearer {pat}"}),
                 allow=(401,), what=f"bearer {name}")
    return c.done(f"{len(routes)} routes 401 anon; {len(OUTSIDE)} outside paths 404; {len(bad)} bad bearers 401")
