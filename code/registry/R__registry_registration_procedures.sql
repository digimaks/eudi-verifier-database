-- registration-api's registry procedures.
-- registration_api_public is the caller; client isolation happens HERE
-- (client_id parameter checked in every procedure that touches client-owned
-- rows) — same discipline as R__registry_procedures.sql. Cross-client
-- access returns registry:not_found (404 via errors.FromResultCode), never a
-- distinguishable 403 (no existence leak).
--
-- One procedure per registrydb.Store method (services/registration-api/
-- internal/registrydb/repo.go). audit-schema writes (audit.append,
-- audit.log_deletion_request, audit.list_deletion_requests) live in
-- audit/R__audit_procedures.sql. Every write procedure in
-- this file threads an `actor` parameter and writes its own audit.entry row
-- atomically with the change it records (transition_client,
-- create_draft_client, save_wrp_document, set_client_registrar_identity,
-- set_client_webhook, add_evidence, purge_offboarded) — every transition is
-- audited atomically with the flip, generalized
-- to every write that has a "who" to attribute.

-- registry.transition_client: THE lifecycle state machine. The ONLY
-- legal edges are the state diagram (ARF Topic 52); anything
-- else is registry:illegal_transition (err:registry:illegal-transition -> 409,
-- app.go RegisterReason). Audited atomically with the flip: who (actor), when
-- (now(), implicit in audit.entry.at), evidence ref, reason.
create or replace procedure registry.transition_client(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_id text := pi_data->>'client_id';
  v_to text := pi_data->>'to_state';
  v_from text;
  v_legal boolean;
begin
  if v_id is null or v_to is null or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid', 'client_id, to_state, actor required');
    return;
  end if;

  select status into v_from from registry.client where id = v_id for update;
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  -- The ONLY legal edges (state machine per ARF Topic 52).
  v_legal := (v_from, v_to) in (
    ('draft','evidence_submitted'),
    ('evidence_submitted','filed_with_registrar'),
    ('filed_with_registrar','registered'),
    ('registered','active'),
    ('active','suspended'),
    ('suspended','active'),
    ('suspended','offboarded'),
    ('active','offboarded'));
  if not v_legal then
    po_data := util.result_error('registry:illegal_transition',
      format('cannot transition %s -> %s', v_from, v_to));
    return;
  end if;

  update registry.client set status = v_to, updated_at = now() where id = v_id;

  -- Audited atomically with the flip (who/when/evidence ref).
  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_id, 'client.transition',
          jsonb_build_object('from', v_from, 'to', v_to,
                             'evidence_ref', pi_data->>'evidence_ref',
                             'reason', pi_data->>'reason'));

  po_data := util.result_success(jsonb_build_object('from', v_from, 'to', v_to));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_client_full: the ClientFull projection (incl. the lifecycle columns
-- slug/wrp_document/contact_emails) — distinct from registry.get_client,
-- which predates those columns and stays as-is for management-api.
create or replace procedure registry.get_client_full(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_row registry.client%rowtype;
begin
  select * into v_row from registry.client where id = pi_data->>'client_id';
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'id', v_row.id, 'name', v_row.name, 'status', v_row.status,
    'registry_uri', v_row.registry_uri, 'client_identifier', v_row.client_identifier,
    'default_webhook_url', v_row.default_webhook_url,
    'allowed_origins', v_row.allowed_origins, 'policy', v_row.policy,
    'slug', v_row.slug, 'wrp_document', v_row.wrp_document,
    'contact_emails', v_row.contact_emails));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.list_clients_by_state: every client, flat (Go groups by status into
-- map[string][]ClientSummary for the dashboard). Not a client-scoped read (no
-- client_id parameter): this is an operator-only aggregate, gated at the route
-- layer, not here.
create or replace procedure registry.list_clients_by_state(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_items jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', c.id, 'name', c.name, 'status', c.status,
           'slug', c.slug, 'updated_at', c.updated_at
         ) order by c.status, c.updated_at desc, c.id desc), '[]'::jsonb)
    into v_items
    from registry.client c;

  po_data := util.result_success(jsonb_build_object('clients', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.create_draft_client: self-registration entry point ([*] -> Draft).
-- registry_uri/client_identifier/default_webhook_url are NOT NULL in the schema
-- but genuinely unknown at draft time (they are registrar-assigned later) —
-- seeded '' here. registry.set_client_registrar_identity (below) is the
-- setter the operator uses to populate registry_uri/client_identifier at
-- filing confirmation. actor is audited (Store.CreateDraftClient threads it
-- for exactly this purpose).
--
-- registry.client.slug (unique) is now ALWAYS populated here, at the earliest
-- lifecycle point — the GET /c/{slug} public registration-info/DPA page and
-- the public deletion form must resolve for any filed_with_registrar+ client,
-- so the slug has to exist well before then; draft creation is the simplest
-- always-present point. The slug is a URL-safe slugified form of the
-- client's name (lowercased, non [a-z0-9] runs collapsed to '-', trimmed,
-- capped at 40 chars) plus a short, deterministic uniqueness suffix drawn
-- from THIS row's own id (v_id is generated explicitly, before the insert,
-- so the suffix is available up front rather than requiring a second
-- statement) — collision-safe even for two clients sharing the exact same
-- name (each gets its own ULID-derived suffix); the column's own UNIQUE
-- constraint is the backstop should the astronomically unlikely collision
-- ever occur anyway (surfaces as registry:error via the "when others"
-- handler below, same as any other unexpected constraint violation this
-- procedure does not special-case).
create or replace procedure registry.create_draft_client(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_id        text;
  v_slug_base text;
  v_slug      text;
begin
  if pi_data->>'name' is null or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid', 'name and actor are required');
    return;
  end if;

  v_id := util.generate_ulid();

  v_slug_base := trim(both '-' from regexp_replace(lower(trim(pi_data->>'name')), '[^a-z0-9]+', '-', 'g'));
  if v_slug_base = '' then
    v_slug_base := 'client';
  end if;
  v_slug_base := trim(trailing '-' from left(v_slug_base, 40));
  v_slug := v_slug_base || '-' || lower(right(v_id, 7));

  insert into registry.client (id, name, registry_uri, client_identifier, default_webhook_url, contact_emails, slug)
  values (
    v_id, pi_data->>'name', '', '', '',
    case when pi_data->>'email' is null then '[]'::jsonb
         else jsonb_build_array(pi_data->>'email') end,
    v_slug);

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_id, 'client.create', jsonb_build_object('name', pi_data->>'name'));

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.set_client_registrar_identity: records the registrar-assigned
-- registry_uri + client_identifier for a client — the setter that
-- populates the two columns registry.create_draft_client seeds as ''.
-- Until it existed, every real ARF TS5 check (internal/ts5check) collapsed to
-- "unavailable" because nothing ever set these two columns past the seed.
-- Wired at filing confirmation (routes/filings.go, the same step that drives
-- evidence_submitted -> filed_with_registrar): this is the point the
-- operator first learns the registrar-assigned identity, and it must be
-- persisted BEFORE the immediate-trigger ARF TS5 poll fires, or that poll
-- still resolves against an empty/relative URI. Audited (actor threaded) —
-- same discipline as every other actor-carrying procedure in this file.
create or replace procedure registry.set_client_registrar_identity(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id         text := pi_data->>'client_id';
  v_registry_uri      text := pi_data->>'registry_uri';
  v_client_identifier text := pi_data->>'client_identifier';
begin
  if v_client_id is null or v_registry_uri is null or v_registry_uri = ''
     or v_client_identifier is null or v_client_identifier = ''
     or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid',
      'client_id, registry_uri, client_identifier, actor are required');
    return;
  end if;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  update registry.client
     set registry_uri = v_registry_uri,
         client_identifier = v_client_identifier,
         updated_at = now()
   where id = v_client_id;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.set_registrar_identity',
          jsonb_build_object('registry_uri', v_registry_uri, 'client_identifier', v_client_identifier));

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Grant co-located with the definition (not the footer below): this
-- procedure is defined in THIS file, so there is no from-zero
-- Evolve-ordering hazard in granting it here — it follows the co-located
-- convention rather than adding to the bulk footer block, to avoid the
-- "grant added to the wrong place / forgotten" class of bug the footer note
-- (below) already warns about for the five shared procedures.
revoke all on procedure registry.set_client_registrar_identity(jsonb, jsonb) from public;
grant execute on procedure registry.set_client_registrar_identity(jsonb, jsonb) to registration_api_public;

-- registry.set_client_webhook: records/replaces a client's
-- default_webhook_url — the setter that closes the last of the
-- "no Store method ever sets this column" gaps (registry_uri/client_identifier
-- and slug are set elsewhere). Without this, no REAL (non-test) client
-- could ever have a populated webhook URL, so neither the ARF TS7
-- deletion-request webhook nor the session-result webhook
-- (management-api's webhook.Deliverer, which reads this SAME column) could
-- ever reach a real client end-to-end. Validates
-- the URL is an ABSOLUTE https URL (defense in depth — routes/clients.go
-- validates the same shape with net/url before ever calling this
-- procedure, but every procedure in this file validates its own inputs
-- regardless of what the Go caller already checked). Audited (actor
-- threaded) — same discipline as set_client_registrar_identity above.
create or replace procedure registry.set_client_webhook(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id   text := pi_data->>'client_id';
  v_webhook_url text := pi_data->>'webhook_url';
begin
  if v_client_id is null or v_webhook_url is null or v_webhook_url = ''
     or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid', 'client_id, webhook_url, actor are required');
    return;
  end if;

  if v_webhook_url !~ '^https://[^[:space:]]+$' then
    po_data := util.result_error('registry:invalid', 'webhook_url must be an absolute https URL');
    return;
  end if;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  update registry.client
     set default_webhook_url = v_webhook_url,
         updated_at = now()
   where id = v_client_id;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.set_webhook',
          jsonb_build_object('webhook_url', v_webhook_url));

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Grant co-located with the definition — same reasoning as
-- set_client_registrar_identity's identical note above.
revoke all on procedure registry.set_client_webhook(jsonb, jsonb) from public;
grant execute on procedure registry.set_client_webhook(jsonb, jsonb) to registration_api_public;

-- registry.set_client_allowed_origins: records/replaces the web origins a
-- client may be invoked from. Same "no Store method ever sets this column"
-- gap set_client_webhook closed for the webhook URL: the column existed and
-- was read on every session create, but nothing could ever write it, so no
-- real client could use the browser-mediated presentation flow at all.
--
-- Replaces the whole list rather than appending: an origin list is a
-- whitelist, and an append-only setter gives no way to withdraw an origin
-- that should no longer be trusted. Passing an empty array is therefore a
-- legitimate, deliberate act — it withdraws the capability.
--
-- Each entry must be a bare web origin: https, host[:port], and nothing else.
-- The comparison made against a caller's real origin later is literal, so a
-- value carrying a path, query, fragment or userinfo would be accepted here
-- and then silently never match. Validated again in this procedure even
-- though the Go caller checks the same shape first — every procedure in this
-- file validates its own inputs regardless. The count is capped because the
-- list is embedded in each request sent out for the client. Audited (actor
-- threaded), as the setters above are.
create or replace procedure registry.set_client_allowed_origins(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id text := pi_data->>'client_id';
  v_origins   jsonb := pi_data->'allowed_origins';
  v_origin    text;
begin
  if v_client_id is null or pi_data->>'actor' is null
     or v_origins is null or jsonb_typeof(v_origins) <> 'array' then
    po_data := util.result_error('registry:invalid',
                                 'client_id, actor and an allowed_origins array are required');
    return;
  end if;

  if jsonb_array_length(v_origins) > 20 then
    po_data := util.result_error('registry:invalid', 'at most 20 allowed origins');
    return;
  end if;

  for v_origin in select jsonb_array_elements_text(v_origins) loop
    -- https://host[:port] only: no path, query, fragment, userinfo or space.
    --
    -- The null test is not redundant. A JSON null element arrives here as SQL
    -- NULL, and NULL !~ '<pattern>' evaluates to NULL rather than true — so
    -- without this the branch never fires for such an element, the loop falls
    -- through, and the whole array is written unvalidated. The stored null
    -- then reaches the verifier as an empty origin, which fails every
    -- browser-flow session this client tries to create until someone edits
    -- the row: a value that can never match, in a list whose entire job is to
    -- match.
    if v_origin is null or v_origin !~ '^https://[^[:space:]/?#@]+$' then
      po_data := util.result_error('registry:invalid',
                                   'each allowed origin must be https://host[:port] with no path, query, fragment or userinfo');
      return;
    end if;
  end loop;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  update registry.client
     set allowed_origins = v_origins,
         updated_at = now()
   where id = v_client_id;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.set_allowed_origins',
          jsonb_build_object('allowed_origins', v_origins));

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Grant co-located with the definition — same reasoning as the setters above.
revoke all on procedure registry.set_client_allowed_origins(jsonb, jsonb) from public;
grant execute on procedure registry.set_client_allowed_origins(jsonb, jsonb) to registration_api_public;

-- registry.set_client_dcapi_mode: records whether this client's browser-based
-- presentation requests are signed or unsigned.
--
-- A signed request lets the wallet authenticate the relying party through its
-- certificate chain and registration data, on top of the web origin the browser
-- asserts. An unsigned request carries neither: the calling origin is the only
-- identity the wallet gets. Both are legitimate — which one a deployment may
-- offer at all is a deployment-wide setting, and this column only chooses
-- between the modes that deployment already permits. A deployment restricted to
-- signed requests ignores an unsigned choice recorded here rather than honouring
-- it, so relaxing one client can never widen the deployment.
--
-- Stored inside the existing policy document (key require_signed_dcapi) rather
-- than in a column of its own: it is one more per-client verification choice
-- alongside the revocation and device-binding ones, and adding a column for each
-- would grow the table for every future toggle. The key is written explicitly
-- even when it matches the default, because "someone chose signed" and "nobody
-- ever decided" are different facts and an auditor reading the row should be
-- able to tell them apart. An absent key still means signed — the safe reading
-- of silence.
--
-- Takes the operator's vocabulary ('signed' / 'unsigned') and translates once,
-- here, so the audit entry records what was asked for rather than the flag it
-- was stored as. Audited (actor threaded), as the setters above are.
create or replace procedure registry.set_client_dcapi_mode(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id text := pi_data->>'client_id';
  v_mode      text := pi_data->>'mode';
begin
  if v_client_id is null or pi_data->>'actor' is null or v_mode is null then
    po_data := util.result_error('registry:invalid',
                                 'client_id, actor and mode are required');
    return;
  end if;

  if v_mode not in ('signed', 'unsigned') then
    po_data := util.result_error('registry:invalid',
                                 'mode must be signed or unsigned');
    return;
  end if;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  update registry.client
     set policy = policy || jsonb_build_object('require_signed_dcapi', v_mode = 'signed'),
         updated_at = now()
   where id = v_client_id;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.set_dcapi_mode',
          jsonb_build_object('mode', v_mode));

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Grant co-located with the definition — same reasoning as the setters above.
revoke all on procedure registry.set_client_dcapi_mode(jsonb, jsonb) from public;
grant execute on procedure registry.set_client_dcapi_mode(jsonb, jsonb) to registration_api_public;

-- registry.save_wrp_document: persists the full ARF TS6 WalletRelyingParty JSON
-- (source of truth) and replaces the intended_use projections — same
-- validate-then-write two-pass shape as registry.set_intended_uses
-- (Pattern A: every entry checked for intended_use_id before any write).
create or replace procedure registry.save_wrp_document(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id text := pi_data->>'client_id';
  v_item      jsonb;
  v_keep      text[] := '{}'::text[];
begin
  if v_client_id is null or pi_data->'doc' is null or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid', 'client_id, doc, actor are required');
    return;
  end if;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  for v_item in select * from jsonb_array_elements(coalesce(pi_data->'intended_uses', '[]'::jsonb))
  loop
    if v_item->>'intended_use_id' is null then
      po_data := util.result_error('registry:invalid', 'intended_use_id is required for every entry');
      return;
    end if;
    v_keep := array_append(v_keep, v_item->>'intended_use_id');
  end loop;

  update registry.client set wrp_document = pi_data->'doc', updated_at = now() where id = v_client_id;

  for v_item in select * from jsonb_array_elements(coalesce(pi_data->'intended_uses', '[]'::jsonb))
  loop
    insert into registry.intended_use (client_id, intended_use_id, purpose, credentials, revoked_at)
    values (
      v_client_id, v_item->>'intended_use_id',
      coalesce(v_item->'purpose', '[]'::jsonb),
      coalesce(v_item->'credentials', '[]'::jsonb),
      nullif(v_item->>'revoked_at', '')::date)
    on conflict (client_id, intended_use_id) do update
      set purpose     = excluded.purpose,
          credentials = excluded.credentials,
          revoked_at  = excluded.revoked_at;
  end loop;

  delete from registry.intended_use
   where client_id = v_client_id
     and not (intended_use_id = any(v_keep));

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.save_wrp_document',
          jsonb_build_object('intended_use_count', coalesce(array_length(v_keep, 1), 0)));

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.add_evidence: content arrives base64-encoded in pi_data (Go marshals
-- []byte to a JSON base64 string); sha256/size are caller-computed
-- server-side from the uploaded multipart file — this
-- procedure trusts and stores them, it does not recompute. size_bytes CHECK
-- (registry/V2, 10 MiB cap) maps to registry:invalid via check_violation.
create or replace procedure registry.add_evidence(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id  text := pi_data->>'client_id';
  v_id         text;
  v_created_at timestamptz;
begin
  if v_client_id is null or pi_data->>'filename' is null or pi_data->>'mime' is null
     or pi_data->>'sha256' is null or pi_data->>'size_bytes' is null
     or pi_data->>'content' is null or pi_data->>'uploaded_by' is null
     or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid',
      'client_id, filename, mime, sha256, size_bytes, content, uploaded_by, actor are required');
    return;
  end if;

  if not exists (select 1 from registry.client where id = v_client_id) then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;

  insert into registry.evidence (client_id, filename, mime, size_bytes, sha256, content, uploaded_by)
  values (
    v_client_id, pi_data->>'filename', pi_data->>'mime', (pi_data->>'size_bytes')::bigint,
    pi_data->>'sha256', decode(pi_data->>'content', 'base64'), pi_data->>'uploaded_by')
  returning id, created_at into v_id, v_created_at;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'evidence.add',
          jsonb_build_object('evidence_id', v_id, 'filename', pi_data->>'filename'));

  po_data := util.result_success(jsonb_build_object('id', v_id, 'created_at', v_created_at));
exception
  when check_violation then
    raise exception '%', util.result_error('registry:invalid', 'evidence size out of bounds') using errcode = 'P0001';
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.list_evidence: metadata only, never content (Evidence Go type has
-- no content field — GetEvidenceContent fetches it separately).
create or replace procedure registry.list_evidence(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_items jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', e.id, 'filename', e.filename, 'mime', e.mime,
           'sha256', e.sha256, 'size_bytes', e.size_bytes, 'created_at', e.created_at
         ) order by e.created_at, e.id), '[]'::jsonb)
    into v_items
    from registry.evidence e
   where e.client_id = pi_data->>'client_id';

  po_data := util.result_success(jsonb_build_object('evidence', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_evidence_content: base64-encoded bytea, scoped to client_id
-- (another client's evidence id reads as registry:not_found — no existence
-- leak, same idiom as get_template).
create or replace procedure registry.get_evidence_content(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_row registry.evidence%rowtype;
begin
  select * into v_row from registry.evidence
   where id = pi_data->>'evidence_id' and client_id = pi_data->>'client_id';
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown evidence');
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'content', encode(v_row.content, 'base64'), 'mime', v_row.mime));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.purge_offboarded: terminal-state cleanup (keys revoked,
-- sessions blocked, data purged per retention). Pattern A: status must
-- already be 'offboarded' (registry:invalid otherwise — not a state
-- transition, so it does not go through transition_client's matrix). Purge
-- semantics: api_keys revoked; evidence BLOB
-- CONTENT is zeroed (metadata — filename/mime/sha256/size — retained for the
-- audit trail); wrp_document / legal-entity data is RETAINED per retention
-- policy — only evidence blobs purge. Audited as 'client.purge'.
create or replace procedure registry.purge_offboarded(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, audit, util, pg_temp
as $$
declare
  v_client_id text := pi_data->>'client_id';
  v_status    text;
begin
  if v_client_id is null or pi_data->>'actor' is null then
    po_data := util.result_error('registry:invalid', 'client_id and actor are required');
    return;
  end if;

  select status into v_status from registry.client where id = v_client_id;
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown client');
    return;
  end if;
  if v_status <> 'offboarded' then
    po_data := util.result_error('registry:invalid', 'client is not offboarded');
    return;
  end if;

  update registry.api_key set revoked_at = coalesce(revoked_at, now()) where client_id = v_client_id;
  update registry.evidence set content = ''::bytea
   where client_id = v_client_id and octet_length(content) > 0;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', v_client_id, 'client.purge', '{}'::jsonb);

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Lock down: EXECUTE only for the service role.
revoke all on procedure registry.transition_client(jsonb, jsonb) from public;
revoke all on procedure registry.get_client_full(jsonb, jsonb) from public;
revoke all on procedure registry.list_clients_by_state(jsonb, jsonb) from public;
revoke all on procedure registry.create_draft_client(jsonb, jsonb) from public;
revoke all on procedure registry.save_wrp_document(jsonb, jsonb) from public;
revoke all on procedure registry.add_evidence(jsonb, jsonb) from public;
revoke all on procedure registry.list_evidence(jsonb, jsonb) from public;
revoke all on procedure registry.get_evidence_content(jsonb, jsonb) from public;
revoke all on procedure registry.purge_offboarded(jsonb, jsonb) from public;

grant execute on procedure registry.transition_client(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.get_client_full(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.list_clients_by_state(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.create_draft_client(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.save_wrp_document(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.add_evidence(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.list_evidence(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.get_evidence_content(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.purge_offboarded(jsonb, jsonb) to registration_api_public;

-- registration-api also calls five procedures defined in
-- registry/R__registry_procedures.sql as-is: registry.set_intended_uses
-- (seed/onboarding upsert), registry.create_api_key / registry.revoke_api_key
-- (issuing keys once a client reaches 'active'),
-- registry.get_client (legacy Client projection, predating the lifecycle
-- columns), and registry.list_intended_uses (the lifecycle
-- service's "-> active" precondition read path —
-- registrydb.Store.ListIntendedUses). Their REVOKE ALL FROM PUBLIC and their
-- registration_api_public GRANT both live in that file, not here, and stay
-- there even now that this file's rename sorts it AFTER
-- R__registry_procedures.sql lexicographically ('R__registry_procedures.sql'
-- < 'R__registry_registration_procedures.sql'): grants belong beside their
-- procedure definitions (house pattern), not
-- duplicated into every caller's own R__ file. This file only ever
-- revokes/grants the 11 procedures it defines itself, so the two files'
-- relative apply order does not matter for correctness either way — proven
-- by the from-zero apply (see README).
