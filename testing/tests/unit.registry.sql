-- SQL unit tests for the registry schema procedures (plpgunit is not wired
-- into this repo yet, so this is a self-contained DO-block script,
-- seed-then-assert, one RAISE EXCEPTION per failed assertion; a clean run
-- prints only NOTICEs + PASS).
--
-- Run as the owner (bypasses the EXECUTE grants so it can freely call every
-- procedure — the role-boundary itself is covered separately by roleleak.sql):
--   psql "$DSN" \
--     -f testing/tests/unit.registry.sql
do $$
declare
  v              jsonb;
  v_client_a     text;
  v_client_b     text;
  v_template_id  text;
  v_key_id       text;
begin
  ------------------------------------------------------------------
  -- Seed: two clients, so every "cross-client" assertion below has a
  -- real second tenant to fail against (not just an unknown id).
  ------------------------------------------------------------------
  v := null;
  call registry.create_client(jsonb_build_object(
    'name', 'Unit Test Client A', 'registry_uri', 'https://reg.example/a',
    'client_identifier', 'sub-unit-a', 'default_webhook_url', 'https://a.example/hook'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_client A failed: %', v; end if;
  v_client_a := v->'data'->>'id';
  if length(v_client_a) is distinct from 26 then raise exception 'expected a 26-char ULID for client A, got: %', v_client_a; end if;

  v := null;
  call registry.create_client(jsonb_build_object(
    'name', 'Unit Test Client B', 'registry_uri', 'https://reg.example/b',
    'client_identifier', 'sub-unit-b', 'default_webhook_url', 'https://b.example/hook'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_client B failed: %', v; end if;
  v_client_b := v->'data'->>'id';

  -- get_client: happy path + unknown id -> registry:not_found
  v := null;
  call registry.get_client(jsonb_build_object('client_id', v_client_a), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.get_client failed: %', v; end if;
  if v->'data'->>'name' is distinct from 'Unit Test Client A' then raise exception 'get_client A mismatch: %', v; end if;
  v := null;
  call registry.get_client('{"client_id":"01JUNKNOWNCLIENTID0000000"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then raise exception 'expected not_found for unknown client, got: %', v; end if;

  ------------------------------------------------------------------
  -- Intended uses: one active, one revoked, both owned by client A.
  ------------------------------------------------------------------
  v := null;
  call registry.set_intended_uses(jsonb_build_object(
    'client_id', v_client_a,
    'intended_uses', jsonb_build_array(
      jsonb_build_object('intended_use_id', 'iu-active', 'purpose', '["age verification"]'::jsonb,
        'credentials', jsonb_build_array(jsonb_build_object(
          'format', 'mso_mdoc', 'doctypes_or_vcts', jsonb_build_array('eu.europa.ec.eudi.pid.1'),
          'all_claims', true))),
      jsonb_build_object('intended_use_id', 'iu-revoked', 'purpose', '["age verification"]'::jsonb,
        'credentials', '[]'::jsonb, 'revoked_at', '2026-01-01')
    )), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_intended_uses failed: %', v; end if;

  -- list_intended_uses: exactly the two seeded rows come back
  v := null;
  call registry.list_intended_uses(jsonb_build_object('client_id', v_client_a), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.list_intended_uses failed: %', v; end if;
  if jsonb_array_length(v->'data'->'intended_uses') is distinct from 2 then
    raise exception 'expected 2 intended uses, got: %', v;
  end if;
  -- another client sees none of them (no cross-client leakage into a list)
  v := null;
  call registry.list_intended_uses(jsonb_build_object('client_id', v_client_b), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.list_intended_uses failed: %', v; end if;
  if v->'data'->'intended_uses' is distinct from '[]'::jsonb then
    raise exception 'expected empty intended_uses for client B, got: %', v;
  end if;

  -- get_intended_use: own vs. cross-client
  v := null;
  call registry.get_intended_use(jsonb_build_object('client_id', v_client_a, 'intended_use_id', 'iu-active'), v);
  if v->>'result' is distinct from 'success' then raise exception 'get_intended_use (own) failed: %', v; end if;
  v := null;
  call registry.get_intended_use(jsonb_build_object('client_id', v_client_b, 'intended_use_id', 'iu-active'), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected not_found for cross-client get_intended_use, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- Templates: create (happy + revoked-intended-use rejection),
  -- get/list/delete with cross-client isolation.
  ------------------------------------------------------------------
  v := null;
  call registry.create_template(jsonb_build_object(
    'client_id', v_client_a, 'name', 'tmpl-1', 'intended_use_id', 'iu-active',
    'dcql_query', '{"credentials":[]}'::jsonb), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_template happy path failed: %', v; end if;
  v_template_id := v->'data'->>'id';
  if v->'data'->>'created_at' is null then raise exception 'create_template missing created_at: %', v; end if;

  -- Pattern A: create_template against a revoked intended use is rejected
  -- BEFORE any write, with the dedicated registry:intended_use_revoked code
  -- (maps to err:registry:intended-use-revoked -> 422, not a generic 4xx).
  v := null;
  call registry.create_template(jsonb_build_object(
    'client_id', v_client_a, 'name', 'tmpl-revoked', 'intended_use_id', 'iu-revoked',
    'dcql_query', '{"credentials":[]}'::jsonb), v);
  if v->>'code' is distinct from 'registry:intended_use_revoked' then
    raise exception 'expected registry:intended_use_revoked, got: %', v;
  end if;

  -- create_template against an intended use that doesn't exist at all (typo,
  -- or belongs to nobody) -> registry:not_found, not intended_use_revoked.
  v := null;
  call registry.create_template(jsonb_build_object(
    'client_id', v_client_a, 'name', 'tmpl-noiu', 'intended_use_id', 'no-such-iu',
    'dcql_query', '{"credentials":[]}'::jsonb), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for unknown intended use, got: %', v;
  end if;

  -- create_template on client A's ACTIVE intended use, but called with
  -- client B's id -> registry:not_found (isolation applies to the intended
  -- use lookup, not just the final row).
  v := null;
  call registry.create_template(jsonb_build_object(
    'client_id', v_client_b, 'name', 'tmpl-cross', 'intended_use_id', 'iu-active',
    'dcql_query', '{"credentials":[]}'::jsonb), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for cross-client create_template, got: %', v;
  end if;

  -- get_template: own vs. cross-client (no existence leak: same code either way)
  v := null;
  call registry.get_template(jsonb_build_object('client_id', v_client_a, 'template_id', v_template_id), v);
  if v->>'result' is distinct from 'success' then raise exception 'get_template (own) failed: %', v; end if;
  v := null;
  call registry.get_template(jsonb_build_object('client_id', v_client_b, 'template_id', v_template_id), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for cross-client get_template, got: %', v;
  end if;

  -- list_templates: only the owner sees it
  v := null;
  call registry.list_templates(jsonb_build_object('client_id', v_client_a), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.list_templates failed: %', v; end if;
  if jsonb_array_length(v->'data'->'templates') is distinct from 1 then
    raise exception 'expected 1 template for client A, got: %', v;
  end if;
  v := null;
  call registry.list_templates(jsonb_build_object('client_id', v_client_b), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.list_templates failed: %', v; end if;
  if v->'data'->'templates' is distinct from '[]'::jsonb then
    raise exception 'expected 0 templates for client B, got: %', v;
  end if;

  -- delete_template: cross-client delete is rejected (Pattern B, P0001)
  begin
    v := null;
    call registry.delete_template(jsonb_build_object('client_id', v_client_b, 'template_id', v_template_id), v);
    raise exception 'expected P0001 for cross-client delete_template';
  exception when sqlstate 'P0001' then
    if sqlerrm::jsonb->>'code' is distinct from 'registry:not_found' then
      raise exception 'expected registry:not_found, got: %', sqlerrm;
    end if;
  end;

  -- delete_template: owner can delete; a second delete is then not_found
  -- (soft-deleted rows read as absent, matching the fail-closed
  -- default and no-existence-leak posture).
  v := null;
  call registry.delete_template(jsonb_build_object('client_id', v_client_a, 'template_id', v_template_id), v);
  if v->>'result' is distinct from 'success' then raise exception 'delete_template (own) failed: %', v; end if;
  v := null;
  call registry.get_template(jsonb_build_object('client_id', v_client_a, 'template_id', v_template_id), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found after delete, got: %', v;
  end if;
  begin
    v := null;
    call registry.delete_template(jsonb_build_object('client_id', v_client_a, 'template_id', v_template_id), v);
    raise exception 'expected P0001 for double-delete';
  exception when sqlstate 'P0001' then
    if sqlerrm::jsonb->>'code' is distinct from 'registry:not_found' then
      raise exception 'expected registry:not_found on double-delete, got: %', sqlerrm;
    end if;
  end;

  ------------------------------------------------------------------
  -- WRPRC: two DISTINCT absent cases, NOT conflated.
  ------------------------------------------------------------------
  -- (a) intended use IS owned but has no current WRPRC (graceful
  -- registrar-reference fallback) -> empty success {}.
  v := null;
  call registry.get_wrprc_for_intended_use(jsonb_build_object('client_id', v_client_a, 'intended_use_id', 'iu-active'), v);
  if v->>'result' is distinct from 'success' or v->'data' is distinct from '{}'::jsonb then
    raise exception 'expected empty success for owned-but-no-wrprc intended use, got: %', v;
  end if;

  -- (a2) cross-service acceptance: a WRPRC that EXISTS for the
  -- intended use but has EXPIRED must resolve as absent too -> empty success
  -- {}, NOT the expired row's data. registry.get_wrprc_for_intended_use's own
  -- WHERE clause already filters `expires_at is null or expires_at > now()`
  -- (registry/R__registry_procedures.sql) -- this proves the filter actually
  -- fires, rather than merely documenting it. This IS the "expired WRPRC ->
  -- requests fall back to the registrar-reference path automatically"
  -- acceptance at the data layer: session creation's
  -- RequestSpec.WRPRC would come back empty here too. The fixture row is
  -- seeded via a direct INSERT (not a procedure call): a later change
  -- dropped the portal-only registry.save_wrprc procedure that used to mint
  -- this row (the registry.wrprc TABLE itself stays — management-api's
  -- registry.get_wrprc_for_intended_use above still reads it), and this
  -- script already runs as the owner, so bypassing the procedure layer here
  -- changes nothing about what's under test.
  insert into registry.wrprc (client_id, intended_use_id, raw, format, expires_at)
  values (v_client_a, 'iu-active', 'expired-wrprc'::bytea, 'jwt', now() - interval '1 day');

  v := null;
  call registry.get_wrprc_for_intended_use(jsonb_build_object('client_id', v_client_a, 'intended_use_id', 'iu-active'), v);
  if v->>'result' is distinct from 'success' or v->'data' is distinct from '{}'::jsonb then
    raise exception 'expected empty success for an EXPIRED wrprc (automatic fallback), got: %', v;
  end if;

  -- (b) intended-use-id NOT owned by this client -> registry:not_found (404,
  -- no existence leak). client B does not own 'iu-active'.
  v := null;
  call registry.get_wrprc_for_intended_use(jsonb_build_object('client_id', v_client_b, 'intended_use_id', 'iu-active'), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for unowned intended use, got: %', v;
  end if;

  -- (c) a wholly-unknown intended-use-id for a real client -> registry:not_found too.
  v := null;
  call registry.get_wrprc_for_intended_use(jsonb_build_object('client_id', v_client_a, 'intended_use_id', 'no-such-iu'), v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for unknown intended use, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- API keys: create, lookup by prefix, revoke; ownership on revoke.
  ------------------------------------------------------------------
  v := null;
  call registry.create_api_key(jsonb_build_object(
    'client_id', v_client_a, 'prefix', 'pfx_unit_test_1', 'secret_hash', '$argon2id$fake'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_api_key failed: %', v; end if;
  v_key_id := v->'data'->>'id';

  v := null;
  call registry.get_client_by_key_prefix('{"prefix":"pfx_unit_test_1"}'::jsonb, v);
  if v->>'result' is distinct from 'success' or v->'data'->>'client_id' is distinct from v_client_a then
    raise exception 'get_client_by_key_prefix mismatch: %', v;
  end if;
  if (v->'data'->>'revoked')::boolean is distinct from false then raise exception 'expected revoked=false, got: %', v; end if;

  v := null;
  call registry.get_client_by_key_prefix('{"prefix":"no-such-prefix"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then raise exception 'expected not_found for unknown prefix, got: %', v; end if;

  -- revoke_api_key: cross-client rejected, owner succeeds
  begin
    v := null;
    call registry.revoke_api_key(jsonb_build_object('client_id', v_client_b, 'key_id', v_key_id), v);
    raise exception 'expected P0001 for cross-client revoke_api_key';
  exception when sqlstate 'P0001' then
    if sqlerrm::jsonb->>'code' is distinct from 'registry:not_found' then
      raise exception 'expected registry:not_found, got: %', sqlerrm;
    end if;
  end;
  v := null;
  call registry.revoke_api_key(jsonb_build_object('client_id', v_client_a, 'key_id', v_key_id), v);
  if v->>'result' is distinct from 'success' then raise exception 'revoke_api_key (own) failed: %', v; end if;

  raise notice 'unit.registry.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.registry.sql: PASS' as result;
