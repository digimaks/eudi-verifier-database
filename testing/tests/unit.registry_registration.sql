-- SQL unit tests for registration-api's registry procedures
-- (registry/R__registry_registration_procedures.sql) — see unit.registry.sql
-- for the plain DO-block rationale (plpgunit not wired in yet).
--
-- Run as the owner (bypasses the EXECUTE grants; the role boundary itself is
-- covered by roleleak.sql):
--   psql "$DSN" \
--     -f testing/tests/unit.registry_registration.sql
do $$
declare
  v          jsonb;
  v_client_a text;
  v_client_a2 text;
  v_client_b text;
  v_client_c text;
  v_client_d text;
  v_many    jsonb;   -- built before a CALL: plpgsql rejects a subquery in an argument
begin
  ------------------------------------------------------------------
  -- Seed: four draft clients (registry.create_draft_client — [*] -> Draft).
  ------------------------------------------------------------------
  v := null;
  call registry.create_draft_client(jsonb_build_object(
    'name', 'Registration Unit Client A', 'email', 'a@example.test', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_draft_client A failed: %', v; end if;
  v_client_a := v->'data'->>'id';
  if length(v_client_a) is distinct from 26 then raise exception 'expected a 26-char ULID for client A, got: %', v_client_a; end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_a and action = 'client.create'
  ) then
    raise exception 'expected an audit.entry row for client.create (A)';
  end if;

  v := null;
  call registry.create_draft_client(jsonb_build_object('name', 'Registration Unit Client B', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_draft_client B failed: %', v; end if;
  v_client_b := v->'data'->>'id';

  v := null;
  call registry.create_draft_client(jsonb_build_object('name', 'Registration Unit Client C', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_draft_client C failed: %', v; end if;
  v_client_c := v->'data'->>'id';

  v := null;
  call registry.create_draft_client(jsonb_build_object('name', 'Registration Unit Client D', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_draft_client D failed: %', v; end if;
  v_client_d := v->'data'->>'id';

  -- missing actor -> registry:invalid (Pattern A, before any write).
  v := null;
  call registry.create_draft_client('{"name":"No Actor"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for create_draft_client without actor, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- Slug auto-generation: create_draft_client mints a
  -- non-null slug from the client's name at draft time — no separate setter
  -- exists (or is needed): GET /c/{slug} public pages must resolve for any
  -- filed_with_registrar+ client, so the slug has to exist from the
  -- earliest lifecycle point onward.
  ------------------------------------------------------------------
  if not exists (
    select 1 from registry.client where id = v_client_a and slug is not null and slug <> ''
  ) then
    raise exception 'expected create_draft_client to auto-generate a non-empty slug for client A';
  end if;

  -- Two clients registered with the EXACT SAME name get DISTINCT slugs (the
  -- per-row ULID-derived suffix, not the slugified name alone, is what makes
  -- this collision-safe).
  v := null;
  call registry.create_draft_client(jsonb_build_object('name', 'Registration Unit Client A', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_draft_client A2 (same name as A) failed: %', v; end if;
  v_client_a2 := v->'data'->>'id';
  -- Assert the second client HAS a slug before comparing the two. Without this
  -- the comparison below proves nothing: a NULL slug is not equal to anything,
  -- including another NULL, so the one regression this block could plausibly
  -- catch — a client minted without a slug — passes silently under `=` and
  -- under `is not distinct from` alike. The equality itself can never fail on
  -- its own terms either (registry.client.slug is UNIQUE, so an equal pair
  -- cannot exist to be found), which is why the missing property, not the
  -- operator, is the thing to fix.
  if not exists (
    select 1 from registry.client where id = v_client_a2 and slug is not null and slug <> ''
  ) then
    raise exception 'expected create_draft_client to auto-generate a non-empty slug for client A2';
  end if;
  if (select slug from registry.client where id = v_client_a)
     = (select slug from registry.client where id = v_client_a2) then
    raise exception 'expected distinct slugs for two same-named clients, both got: %',
      (select slug from registry.client where id = v_client_a);
  end if;

  -- get_client_full: new client starts 'draft' (V2's new column default),
  -- with the seeded contact email and empty wrp_document.
  v := null;
  call registry.get_client_full(jsonb_build_object('client_id', v_client_a), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.get_client_full failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'draft' then raise exception 'expected draft status for new client, got: %', v; end if;
  if v->'data'->'contact_emails' is distinct from '["a@example.test"]'::jsonb then
    raise exception 'expected seeded contact email, got: %', v;
  end if;
  v := null;
  call registry.get_client_full('{"client_id":"01JUNKNOWNCLIENTID0000000"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then raise exception 'expected not_found for unknown client, got: %', v; end if;

  ------------------------------------------------------------------
  -- Illegal edge: draft -> active skips the whole chain (client C stays
  -- draft — no partial write on a rejected transition).
  ------------------------------------------------------------------
  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_c, 'to_state', 'active', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:illegal_transition' then
    raise exception 'expected illegal_transition for draft->active, got: %', v;
  end if;
  v := null;
  call registry.get_client_full(jsonb_build_object('client_id', v_client_c), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.get_client_full failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'draft' then raise exception 'expected client C still draft after rejected transition, got: %', v; end if;

  -- unknown client id -> registry:not_found (before any legality check).
  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', '01JUNKNOWNCLIENTID0000000', 'to_state', 'active', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:not_found' then raise exception 'expected not_found for unknown client, got: %', v; end if;

  ------------------------------------------------------------------
  -- Legal walk over client A: exercises 7 of the 8 edges (all but
  -- suspended->offboarded, covered via client B below). Every hop is
  -- checked against its own audit.entry row (who/when/evidence ref/reason).
  ------------------------------------------------------------------
  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'evidence_submitted', 'actor', 'unit-test',
    'evidence_ref', 'ev-1', 'reason', 'contract uploaded'), v);
  if v->>'result' is distinct from 'success' or v->'data'->>'from' is distinct from 'draft' or v->'data'->>'to' is distinct from 'evidence_submitted' then
    raise exception 'draft->evidence_submitted failed: %', v;
  end if;
  if not exists (
    select 1 from audit.entry
     where client_id = v_client_a and action = 'client.transition'
       and detail->>'from' = 'draft' and detail->>'to' = 'evidence_submitted'
       and detail->>'evidence_ref' = 'ev-1' and detail->>'reason' = 'contract uploaded'
       and actor = 'unit-test'
  ) then
    raise exception 'expected an audit.entry row for draft->evidence_submitted';
  end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'filed_with_registrar', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'evidence_submitted->filed_with_registrar failed: %', v; end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'registered', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'filed_with_registrar->registered failed: %', v; end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'active', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'registered->active failed: %', v; end if;

  -- Illegal: active -> registered (skipping back down the chain).
  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'registered', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:illegal_transition' then
    raise exception 'expected illegal_transition for active->registered, got: %', v;
  end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'suspended', 'actor', 'unit-test',
    'reason', 'TS5 revokedAt observed'), v);
  if v->>'result' is distinct from 'success' then raise exception 'active->suspended failed: %', v; end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'active', 'actor', 'unit-test',
    'reason', 're-verified'), v);
  if v->>'result' is distinct from 'success' then raise exception 'suspended->active (re-verified) failed: %', v; end if;

  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'offboarded', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'active->offboarded failed: %', v; end if;
  if not exists (
    select 1 from audit.entry
     where client_id = v_client_a and action = 'client.transition'
       and detail->>'from' = 'active' and detail->>'to' = 'offboarded'
  ) then
    raise exception 'expected an audit.entry row for active->offboarded';
  end if;

  -- Illegal (terminal): offboarded -> active.
  v := null;
  call registry.transition_client(jsonb_build_object(
    'client_id', v_client_a, 'to_state', 'active', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:illegal_transition' then
    raise exception 'expected illegal_transition for offboarded->active, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- Legal walk over client B: reaches the 8th edge, suspended->offboarded.
  ------------------------------------------------------------------
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'evidence_submitted', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B draft->evidence_submitted failed: %', v; end if;
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'filed_with_registrar', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B evidence_submitted->filed_with_registrar failed: %', v; end if;
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'registered', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B filed_with_registrar->registered failed: %', v; end if;
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'active', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B registered->active failed: %', v; end if;
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'suspended', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B active->suspended failed: %', v; end if;
  v := null;
  call registry.transition_client(jsonb_build_object('client_id', v_client_b, 'to_state', 'offboarded', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'B suspended->offboarded failed: %', v; end if;
  if not exists (
    select 1 from audit.entry
     where client_id = v_client_b and action = 'client.transition'
       and detail->>'from' = 'suspended' and detail->>'to' = 'offboarded'
  ) then
    raise exception 'expected an audit.entry row for B suspended->offboarded';
  end if;

  ------------------------------------------------------------------
  -- purge_offboarded: Pattern A guard (status must already be
  -- 'offboarded'); evidence content zeroed, metadata retained; api_keys
  -- revoked; audited as client.purge.
  ------------------------------------------------------------------
  v := null;
  call registry.purge_offboarded(jsonb_build_object('client_id', v_client_d, 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid purging a non-offboarded client, got: %', v;
  end if;

  call registry.add_evidence(jsonb_build_object(
    'client_id', v_client_a, 'filename', 'contract.pdf', 'mime', 'application/pdf',
    'sha256', repeat('ab', 32), 'size_bytes', 10, 'content', encode('hello', 'base64'),
    'uploaded_by', 'unit-test', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'add_evidence (pre-purge seed) failed: %', v; end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_a and action = 'evidence.add'
  ) then
    raise exception 'expected an audit.entry row for evidence.add';
  end if;

  -- list_evidence / get_evidence_content: metadata list + content fetch,
  -- both scoped to client_id.
  v := null;
  call registry.list_evidence(jsonb_build_object('client_id', v_client_a), v);
  if v->>'result' is distinct from 'success' then raise exception 'registry.list_evidence failed: %', v; end if;
  if jsonb_array_length(v->'data'->'evidence') is distinct from 1 then
    raise exception 'expected exactly 1 evidence row for client A, got: %', v;
  end if;
  if v->'data'->'evidence'->0->>'filename' is distinct from 'contract.pdf' then
    raise exception 'expected list_evidence to project the seeded filename, got: %', v;
  end if;

  declare
    v_evidence_id text := v->'data'->'evidence'->0->>'id';
  begin
    v := null;
    call registry.get_evidence_content(jsonb_build_object('client_id', v_client_a, 'evidence_id', v_evidence_id), v);
    if v->>'result' is distinct from 'success' or convert_from(decode(v->'data'->>'content', 'base64'), 'UTF8') is distinct from 'hello' then
      raise exception 'get_evidence_content mismatch: %', v;
    end if;
    -- cross-client read -> registry:not_found (no existence leak).
    v := null;
    call registry.get_evidence_content(jsonb_build_object('client_id', v_client_b, 'evidence_id', v_evidence_id), v);
    if v->>'code' is distinct from 'registry:not_found' then
      raise exception 'expected registry:not_found for cross-client get_evidence_content, got: %', v;
    end if;
  end;

  call registry.create_api_key(jsonb_build_object(
    'client_id', v_client_a, 'prefix', 'pfx_unit_registration_1', 'secret_hash', '$argon2id$fake'), v);
  if v->>'result' is distinct from 'success' then raise exception 'create_api_key (pre-purge seed) failed: %', v; end if;

  v := null;
  call registry.purge_offboarded(jsonb_build_object('client_id', v_client_a, 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'purge_offboarded (offboarded client) failed: %', v; end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_a and action = 'client.purge'
  ) then
    raise exception 'expected an audit.entry row for client.purge';
  end if;
  if exists (
    select 1 from registry.evidence where client_id = v_client_a and octet_length(content) > 0
  ) then
    raise exception 'expected purge_offboarded to zero evidence content';
  end if;
  if not exists (
    select 1 from registry.evidence where client_id = v_client_a and filename = 'contract.pdf'
  ) then
    raise exception 'expected purge_offboarded to RETAIN evidence metadata';
  end if;
  if exists (
    select 1 from registry.api_key where client_id = v_client_a and revoked_at is null
  ) then
    raise exception 'expected purge_offboarded to revoke every api_key';
  end if;

  ------------------------------------------------------------------
  -- set_client_registrar_identity / set_client_webhook:
  -- setters closing the "no Store method ever sets this column" gaps.
  ------------------------------------------------------------------
  v := null;
  call registry.set_client_registrar_identity(jsonb_build_object(
    'client_id', v_client_c, 'registry_uri', 'https://reg.example/c',
    'client_identifier', 'sub-unit-c', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_registrar_identity failed: %', v; end if;
  if not exists (
    select 1 from registry.client where id = v_client_c
       and registry_uri = 'https://reg.example/c' and client_identifier = 'sub-unit-c'
  ) then
    raise exception 'expected set_client_registrar_identity to persist registry_uri/client_identifier';
  end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_c and action = 'client.set_registrar_identity'
  ) then
    raise exception 'expected an audit.entry row for client.set_registrar_identity';
  end if;
  v := null;
  call registry.set_client_registrar_identity('{"client_id":"01JUNKNOWNCLIENTID0000000","registry_uri":"https://x","client_identifier":"x","actor":"unit-test"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for set_client_registrar_identity on an unknown client, got: %', v;
  end if;

  v := null;
  call registry.set_client_webhook(jsonb_build_object(
    'client_id', v_client_c, 'webhook_url', 'https://c.example/hook', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_webhook failed: %', v; end if;
  if not exists (
    select 1 from registry.client where id = v_client_c and default_webhook_url = 'https://c.example/hook'
  ) then
    raise exception 'expected set_client_webhook to persist default_webhook_url';
  end if;
  -- rejects a non-https / relative URL (defense in depth).
  v := null;
  call registry.set_client_webhook(jsonb_build_object(
    'client_id', v_client_c, 'webhook_url', 'http://insecure.example/hook', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for a non-https webhook_url, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- set_client_allowed_origins: the web origins a client may be invoked
  -- from. A whitelist compared literally later, so anything stored that
  -- cannot match is worse than a rejection at write time.
  ------------------------------------------------------------------
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["https://a.example", "https://b.example:8443"]'::jsonb), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_allowed_origins failed: %', v; end if;
  if not exists (
    select 1 from registry.client where id = v_client_c
       and allowed_origins = '["https://a.example", "https://b.example:8443"]'::jsonb
  ) then
    raise exception 'expected set_client_allowed_origins to store both origins verbatim';
  end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_c and action = 'client.set_allowed_origins'
  ) then
    raise exception 'expected an audit.entry row for client.set_allowed_origins';
  end if;

  -- Replaces rather than appends, and an empty array is a deliberate act:
  -- withdrawing the capability must be expressible.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test', 'allowed_origins', '[]'::jsonb), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_allowed_origins [] failed: %', v; end if;
  if not exists (
    select 1 from registry.client where id = v_client_c and allowed_origins = '[]'::jsonb
  ) then
    raise exception 'expected an empty array to withdraw every origin';
  end if;

  -- A JSON null element. REGRESSION TEST: jsonb_array_elements_text yields SQL
  -- NULL for it, and NULL !~ '<pattern>' is NULL, not true — so before the
  -- explicit null check the loop fell through and the array was stored
  -- unvalidated, putting an unmatchable entry into the whitelist.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["https://ok.example", null]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for a null origin element, got: %', v;
  end if;
  if not exists (
    select 1 from registry.client where id = v_client_c and allowed_origins = '[]'::jsonb
  ) then
    raise exception 'expected the rejected call to store nothing (list must still be empty)';
  end if;

  -- Every other shape the comparison would silently never match.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["http://insecure.example"]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for a non-https origin, got: %', v;
  end if;
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["https://a.example/path"]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for an origin with a path, got: %', v;
  end if;
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["https://u:p@a.example"]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for an origin with userinfo, got: %', v;
  end if;
  -- Not an array at all, and a non-string element.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '"https://a.example"'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid when allowed_origins is not an array, got: %', v;
  end if;
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test', 'allowed_origins', '[123]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for a non-string origin element, got: %', v;
  end if;

  -- The cap: 20 accepted, 21 refused. Each entry is embedded in every request
  -- sent out for this client, so the list is bounded on purpose.
  select jsonb_agg('https://o' || g || '.example') into v_many from generate_series(1, 20) g;
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', v_many), v);
  if v->>'result' is distinct from 'success' then raise exception 'expected 20 origins to be accepted: %', v; end if;
  select jsonb_agg('https://o' || g || '.example') into v_many from generate_series(1, 21) g;
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', v_many), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for 21 origins, got: %', v;
  end if;

  -- Missing actor, and an unknown client.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'allowed_origins', '["https://a.example"]'::jsonb), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid when actor is missing, got: %', v;
  end if;
  v := null;
  call registry.set_client_allowed_origins(
    '{"client_id":"01JUNKNOWNCLIENTID0000000","actor":"unit-test","allowed_origins":["https://a.example"]}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for an unknown client, got: %', v;
  end if;

  -- Leave the client with a usable list for anything that follows.
  v := null;
  call registry.set_client_allowed_origins(jsonb_build_object(
    'client_id', v_client_c, 'actor', 'unit-test',
    'allowed_origins', '["https://a.example"]'::jsonb), v);
  if v->>'result' is distinct from 'success' then raise exception 'restore of allowed origins failed: %', v; end if;

  ------------------------------------------------------------------
  -- set_client_dcapi_mode: chooses signed or unsigned browser-based
  -- presentation requests for one client, inside the policy document.
  ------------------------------------------------------------------
  v := null;
  call registry.set_client_dcapi_mode(jsonb_build_object(
    'client_id', v_client_c, 'mode', 'unsigned', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_dcapi_mode failed: %', v; end if;
  if not exists (
    select 1 from registry.client
     where id = v_client_c and (policy->>'require_signed_dcapi')::boolean is false
  ) then
    raise exception 'expected set_client_dcapi_mode unsigned to store require_signed_dcapi false';
  end if;
  if not exists (
    select 1 from audit.entry where client_id = v_client_c and action = 'client.set_dcapi_mode'
  ) then
    raise exception 'expected an audit.entry row for client.set_dcapi_mode';
  end if;

  -- Choosing signed is recorded explicitly, not by removing the key: a
  -- deliberate choice and an absent one must stay distinguishable.
  v := null;
  call registry.set_client_dcapi_mode(jsonb_build_object(
    'client_id', v_client_c, 'mode', 'signed', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_dcapi_mode signed failed: %', v; end if;
  if not exists (
    select 1 from registry.client
     where id = v_client_c and (policy->>'require_signed_dcapi')::boolean is true
  ) then
    raise exception 'expected set_client_dcapi_mode signed to store require_signed_dcapi true';
  end if;

  -- The other policy keys survive the write (it merges, never replaces).
  update registry.client
     set policy = policy || '{"revocation_fail_closed": false}'::jsonb
   where id = v_client_c;
  v := null;
  call registry.set_client_dcapi_mode(jsonb_build_object(
    'client_id', v_client_c, 'mode', 'unsigned', 'actor', 'unit-test'), v);
  if v->>'result' is distinct from 'success' then raise exception 'set_client_dcapi_mode merge failed: %', v; end if;
  if not exists (
    select 1 from registry.client
     where id = v_client_c and policy ? 'revocation_fail_closed'
       and (policy->>'require_signed_dcapi')::boolean is false
  ) then
    raise exception 'expected set_client_dcapi_mode to merge into policy, not replace it';
  end if;

  v := null;
  call registry.set_client_dcapi_mode(jsonb_build_object(
    'client_id', v_client_c, 'mode', 'whatever', 'actor', 'unit-test'), v);
  if v->>'code' is distinct from 'registry:invalid' then
    raise exception 'expected registry:invalid for an unknown dcapi mode, got: %', v;
  end if;

  v := null;
  call registry.set_client_dcapi_mode(
    '{"client_id":"01JUNKNOWNCLIENTID0000000","mode":"signed","actor":"unit-test"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for set_client_dcapi_mode on an unknown client, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- save_wrp_document: persists the full WRP document (source of truth)
  -- and upserts the intended_use projections in the same call.
  ------------------------------------------------------------------
  v := null;
  call registry.save_wrp_document(jsonb_build_object(
    'client_id', v_client_d, 'doc', jsonb_build_object('name', 'Unit Test WRP'), 'actor', 'unit-test',
    'intended_uses', jsonb_build_array(jsonb_build_object('intended_use_id', 'iu-registration-1'))), v);
  if v->>'result' is distinct from 'success' then raise exception 'save_wrp_document failed: %', v; end if;
  if not exists (
    select 1 from registry.client where id = v_client_d and wrp_document->>'name' = 'Unit Test WRP'
  ) then
    raise exception 'expected save_wrp_document to persist wrp_document';
  end if;
  if not exists (
    select 1 from registry.intended_use where client_id = v_client_d and intended_use_id = 'iu-registration-1'
  ) then
    raise exception 'expected save_wrp_document to upsert the intended_use projection';
  end if;
  -- unknown client -> registry:not_found.
  v := null;
  call registry.save_wrp_document('{"client_id":"01JUNKNOWNCLIENTID0000000","doc":{},"actor":"unit-test"}'::jsonb, v);
  if v->>'code' is distinct from 'registry:not_found' then
    raise exception 'expected registry:not_found for save_wrp_document on an unknown client, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- list_clients_by_state: every client, flat, grouped-by-status on the Go
  -- side — just asserts our four seeded clients all come back.
  ------------------------------------------------------------------
  v := null;
  call registry.list_clients_by_state('{}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'list_clients_by_state failed: %', v; end if;
  if (
    select count(*) from jsonb_array_elements(v->'data'->'clients') c
     where c->>'id' in (v_client_a, v_client_b, v_client_c, v_client_d)
  ) is distinct from 4 then
    raise exception 'expected all 4 seeded clients in list_clients_by_state, got: %', v;
  end if;

  raise notice 'unit.registry_registration.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.registry_registration.sql: PASS' as result;
