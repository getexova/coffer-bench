-- Coffer role and grant block (docs/CONTRACTS.md §6, verbatim in substance).
--
-- This file is applied twice by design:
--   1. inside the transaction that applies 0001_init.sql, because the grants can
--      only be created once the tables exist and they must commit or roll back
--      together with them;
--   2. on every later boot, unconditionally, because a restore from a
--      `pg_dump --no-owner --no-privileges` dump brings schema_migrations back
--      populated and carries no GRANT statements with it. Re-applying here is what
--      makes a restored stack usable without a manual step.
--
-- Every statement is idempotent, so running it repeatedly is safe.
--
-- `<owner>` in the frozen contract is resolved at execution time from current_user,
-- which is the role the migration runner connected as. The runner refuses to apply
-- this block without a known owner identity.
--
-- coffer_app owns nothing, is not a member of the owner role, and has no CREATE on
-- the schema, so it cannot ALTER TABLE ... DROP TRIGGER or re-grant itself.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffer_app') THEN
    CREATE ROLE coffer_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

REVOKE ALL ON audit_events FROM PUBLIC;
GRANT SELECT, INSERT ON audit_events TO coffer_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  organizations, users, personal_access_tokens, projects, environments,
  project_grants, service_tokens, project_data_keys, secrets, secret_versions,
  change_requests TO coffer_app;
GRANT SELECT, INSERT, UPDATE ON audit_heads TO coffer_app;   -- append advances the head
-- The runtime role must be able to read schema_migrations: /readyz answers 200 only
-- when every embedded migration version is present, and that check runs on the runtime
-- pool. Without this grant the check fails with "permission denied" and a healthy
-- server reports not_ready forever. SELECT only: the runner owns the writes.
GRANT SELECT ON schema_migrations TO coffer_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO coffer_app;
GRANT USAGE ON SCHEMA public TO coffer_app;                  -- no CREATE

DO $$
DECLARE
  owner_name text := current_user;
BEGIN
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO coffer_app',
    owner_name);
  EXECUTE format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO coffer_app',
    owner_name);
END $$;
