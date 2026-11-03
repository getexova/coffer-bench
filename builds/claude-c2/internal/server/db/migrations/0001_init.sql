-- Coffer schema v1 (CONTRACT §3). Idempotent: safe to re-run.

CREATE TABLE IF NOT EXISTS orgs (
    id          text PRIMARY KEY,
    slug        text UNIQUE NOT NULL,
    disabled    boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE IF NOT EXISTS users (
    id                   text PRIMARY KEY,
    org_id               text NULL REFERENCES orgs(id),
    email                text NOT NULL,
    email_norm           text UNIQUE NOT NULL,
    password_hash        text NOT NULL,
    role                 text NOT NULL CHECK (role IN ('platform_admin','owner','admin','member')),
    must_change_password boolean NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now(),
    password_changed_at  timestamptz,
    CHECK ((role = 'platform_admin') = (org_id IS NULL))
);
CREATE INDEX IF NOT EXISTS users_org_idx ON users (org_id);

CREATE TABLE IF NOT EXISTS login_failures (
    email_norm text NOT NULL,
    failed_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_idx ON login_failures (email_norm, failed_at);

CREATE TABLE IF NOT EXISTS projects (
    id          text PRIMARY KEY,
    org_id      text NOT NULL REFERENCES orgs(id),
    slug        text NOT NULL,
    wrapped_dek bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS environments (
    id         text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects(id),
    slug       text NOT NULL,
    protected  boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    UNIQUE (project_id, slug)
);

CREATE TABLE IF NOT EXISTS tokens (
    id           text PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('pat','service')),
    token_hash   bytea UNIQUE NOT NULL,
    org_id       text NULL REFERENCES orgs(id),
    user_id      text NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by   text NULL,
    project_id   text NULL REFERENCES projects(id),
    env_id       text NULL REFERENCES environments(id),
    access       text NULL CHECK (access IN ('read','read-write')),
    name         text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    CHECK ((kind = 'pat' AND user_id IS NOT NULL AND project_id IS NULL AND env_id IS NULL AND access IS NULL)
        OR (kind = 'service' AND user_id IS NULL AND org_id IS NOT NULL AND project_id IS NOT NULL
            AND env_id IS NOT NULL AND access IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS tokens_org_kind_idx ON tokens (org_id, kind);
CREATE INDEX IF NOT EXISTS tokens_user_idx ON tokens (user_id);

CREATE TABLE IF NOT EXISTS grants (
    user_id    text REFERENCES users(id) ON DELETE CASCADE,
    project_id text REFERENCES projects(id),
    level      text NOT NULL CHECK (level IN ('viewer','reader','writer')),
    created_at timestamptz DEFAULT now(),
    PRIMARY KEY (user_id, project_id)
);

CREATE TABLE IF NOT EXISTS secrets (
    env_id          text REFERENCES environments(id),
    key             text,
    current_version int NOT NULL,
    deleted         boolean NOT NULL,
    updated_at      timestamptz NOT NULL,
    updated_by      text NOT NULL,
    PRIMARY KEY (env_id, key)
);

CREATE TABLE IF NOT EXISTS secret_versions (
    env_id     text,
    key        text,
    version    int,
    deleted    boolean NOT NULL,
    ciphertext bytea NULL,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    PRIMARY KEY (env_id, key, version),
    FOREIGN KEY (env_id, key) REFERENCES secrets(env_id, key),
    CHECK (deleted = (ciphertext IS NULL))
);

CREATE TABLE IF NOT EXISTS change_requests (
    id               text PRIMARY KEY,
    org_id           text NOT NULL REFERENCES orgs(id),
    project_id       text NOT NULL REFERENCES projects(id),
    env_id           text NOT NULL REFERENCES environments(id),
    key              text NOT NULL,
    op               text NOT NULL CHECK (op IN ('set','delete','rollback')),
    ciphertext       bytea NULL,
    rollback_to      int NULL,
    expected_version int NULL,
    base_version     int NOT NULL,
    status           text NOT NULL CHECK (status IN ('pending','approved','rejected','stale')),
    proposed_by      text NOT NULL,
    proposed_by_user text NULL,
    decided_by       text NULL,
    decided_at       timestamptz NULL,
    applied_version  int NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS change_requests_org_idx ON change_requests (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_chains (
    chain     text PRIMARY KEY,
    last_seq  bigint NOT NULL,
    last_hash text NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    chain      text,
    seq        bigint,
    ts         timestamptz NOT NULL,
    org_id     text NULL,
    actor_type text,
    actor_id   text,
    action     text,
    target     text,
    source_ip  text,
    result     text CHECK (result IN ('success','denied','failed')),
    details    jsonb NOT NULL DEFAULT '{}',
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    PRIMARY KEY (chain, seq)
);

CREATE TABLE IF NOT EXISTS master_key_check (
    id      int PRIMARY KEY CHECK (id = 1),
    wrapped bytea NOT NULL
);

-- Audit rows are append-only (defense in depth; the app role also lacks the
-- UPDATE/DELETE privilege). BEFORE triggers so a DB owner can drop them to
-- simulate tampering in tests.
CREATE OR REPLACE FUNCTION coffer_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION coffer_audit_immutable();

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION coffer_audit_immutable();
