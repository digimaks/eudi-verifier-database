-- Acceptance: management_public direct table access must FAIL.
-- Run as the owner (digimaks ) — SET ROLE requires membership/superuser, which
-- the dev owner has: docker compose's POSTGRES_USER bootstraps as superuser.
--   psql "postgresql://digimaks :verifier_dev@localhost:55432/digimaks " -f testing/roleleak.sql
-- Expected: no ROLE LEAK exception raised (only NOTICEs and a final PASS).
set role management_public;
do $$ begin
  begin
    perform count(*) from registry.client;
    raise exception 'ROLE LEAK: management_public can SELECT registry.client';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from session.session;
    raise exception 'ROLE LEAK: management_public can SELECT session.session';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

-- Extra coverage beyond the minimal check: every registry table, and
-- write access too (SELECT-only leaks are not the only failure mode).
set role management_public;
do $$
declare
  v jsonb;
begin
  begin
    perform count(*) from registry.intended_use;
    raise exception 'ROLE LEAK: management_public can SELECT registry.intended_use';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from registry.template;
    raise exception 'ROLE LEAK: management_public can SELECT registry.template';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from registry.api_key;
    raise exception 'ROLE LEAK: management_public can SELECT registry.api_key';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from registry.wrprc;
    raise exception 'ROLE LEAK: management_public can SELECT registry.wrprc';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from session.verification_report;
    raise exception 'ROLE LEAK: management_public can SELECT session.verification_report';
  exception when insufficient_privilege then null; end;
  begin
    insert into registry.client (name, registry_uri, client_identifier, default_webhook_url)
    values ('x', 'https://x', 'x', 'https://x');
    raise exception 'ROLE LEAK: management_public can INSERT into registry.client';
  exception when insufficient_privilege then null; end;
  begin
    -- management_public is never granted EXECUTE on eudi-verifier-core-only
    -- procedures either (session.create_session, session.save_report):
    -- client isolation is a role-boundary property, not just a table one.
    v := null;
    call session.create_session('{}'::jsonb, v);
    raise exception 'ROLE LEAK: management_public can CALL session.create_session';
  exception when insufficient_privilege then null; end;
  begin
    v := null;
    call session.save_report('{}'::jsonb, v);
    raise exception 'ROLE LEAK: management_public can CALL session.save_report';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

select 'ROLELEAK: PASS — management_public has no table access and no create_session/save_report EXECUTE' as result;

-- registration_api_public leak checks — same shape as the
-- management_public block above, plus the audit schema's append-only
-- guarantee: registration_api_public must not be able
-- to SELECT/INSERT/UPDATE/DELETE registry or audit tables directly, and
-- specifically must not be able to mutate audit.entry even though it DOES
-- have EXECUTE on audit.append (INSERT-only via the procedure, never a raw
-- UPDATE/DELETE).
set role registration_api_public;
do $$
declare
  v jsonb;
begin
  begin
    perform count(*) from registry.client;
    raise exception 'ROLE LEAK: registration_api_public can SELECT registry.client';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from registry.evidence;
    raise exception 'ROLE LEAK: registration_api_public can SELECT registry.evidence';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from audit.entry;
    raise exception 'ROLE LEAK: registration_api_public can SELECT audit.entry';
  exception when insufficient_privilege then null; end;
  begin
    perform count(*) from audit.deletion_request;
    raise exception 'ROLE LEAK: registration_api_public can SELECT audit.deletion_request';
  exception when insufficient_privilege then null; end;
  begin
    insert into registry.client (name, registry_uri, client_identifier, default_webhook_url)
    values ('x', 'https://x', 'x', 'https://x');
    raise exception 'ROLE LEAK: registration_api_public can INSERT into registry.client';
  exception when insufficient_privilege then null; end;
  begin
    -- No table grants at all — even a direct INSERT into the
    -- append-only audit.entry table (not through audit.append) must fail on
    -- the GRANT boundary, before the guard trigger is ever reached.
    insert into audit.entry (actor, action) values ('x', 'x');
    raise exception 'ROLE LEAK: registration_api_public can INSERT into audit.entry directly';
  exception when insufficient_privilege then null; end;
  begin
    update audit.entry set action = 'x';
    raise exception 'ROLE LEAK: registration_api_public can UPDATE audit.entry';
  exception when insufficient_privilege then null; end;
  begin
    delete from audit.entry;
    raise exception 'ROLE LEAK: registration_api_public can DELETE audit.entry';
  exception when insufficient_privilege then null; end;
  begin
    -- Same append-only guarantee for audit.deletion_request (ARF TS7 log) — only
    -- SELECT was covered above; mirror the audit.entry block's INSERT/
    -- UPDATE/DELETE denial so a direct write (not through
    -- audit.log_deletion_request) is blocked at the grant boundary too.
    insert into audit.deletion_request (client_id, session_id, attribute_names)
    values ('x', 'x', '[]'::jsonb);
    raise exception 'ROLE LEAK: registration_api_public can INSERT into audit.deletion_request directly';
  exception when insufficient_privilege then null; end;
  begin
    update audit.deletion_request set session_id = 'x';
    raise exception 'ROLE LEAK: registration_api_public can UPDATE audit.deletion_request';
  exception when insufficient_privilege then null; end;
  begin
    delete from audit.deletion_request;
    raise exception 'ROLE LEAK: registration_api_public can DELETE audit.deletion_request';
  exception when insufficient_privilege then null; end;
  begin
    -- management_public-only procedures must stay out of reach too —
    -- the *_public roles are siloed from each other, not just from the owner.
    v := null;
    call registry.create_template('{}'::jsonb, v);
    raise exception 'ROLE LEAK: registration_api_public can CALL registry.create_template';
  exception when insufficient_privilege then null; end;
  begin
    v := null;
    call session.create_session('{}'::jsonb, v);
    raise exception 'ROLE LEAK: registration_api_public can CALL session.create_session';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

select 'ROLELEAK: PASS — registration_api_public has no table access and the audit append-only guarantee holds against the grant boundary too' as result;

-- Negative-role assertions for the
-- registration_api_public-only procedures added SINCE the original
-- registration_api_public block above was written —
-- set_client_registrar_identity and
-- set_client_webhook. Mirrors this file's existing pattern
-- EXACTLY (management_public must not reach ANY registration_api_public-only
-- procedure, not just the tables) — the *_public roles are siloed from each
-- other, not just from the owner. (A later change dropped the portal-only
-- provision_client_user / list_latest_ts5_per_client / list_pending_filings
-- procedures this block used to also assert against.)
set role management_public;
do $$
declare
  v jsonb;
begin
  begin
    v := null;
    call registry.set_client_registrar_identity('{}'::jsonb, v);
    raise exception 'ROLE LEAK: management_public can CALL registry.set_client_registrar_identity';
  exception when insufficient_privilege then null; end;
  begin
    v := null;
    call registry.set_client_webhook('{}'::jsonb, v);
    raise exception 'ROLE LEAK: management_public can CALL registry.set_client_webhook';
  exception when insufficient_privilege then null; end;
end $$;
reset role;

select 'ROLELEAK: PASS — management_public cannot reach any registration_api_public-only procedure' as result;
