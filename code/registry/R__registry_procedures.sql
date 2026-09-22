-- registry procedures. management_public is the only
-- caller; client isolation happens HERE (client_id parameter checked in every
-- procedure that touches client-owned rows). Cross-client access returns
-- registry:not_found (→ 404 via errors.FromResultCode; no existence leak).

create or replace procedure registry.get_client_by_key_prefix(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_rec record;
begin
  if pi_data->>'prefix' is null then
    po_data := util.result_error('registry:invalid', 'prefix is required');
    return;
  end if;

  select k.id as key_id, k.client_id, k.secret_hash,
         (k.revoked_at is not null) as revoked, c.status as client_status
    into v_rec
    from registry.api_key k
    join registry.client c on c.id = k.client_id
   where k.prefix = pi_data->>'prefix';

  if not found then
    po_data := util.result_error('registry:not_found', 'unknown key');
    return;
  end if;

  update registry.api_key set last_used_at = now() where id = v_rec.key_id;

  po_data := util.result_success(jsonb_build_object(
    'key_id', v_rec.key_id, 'client_id', v_rec.client_id,
    'secret_hash', v_rec.secret_hash, 'revoked', v_rec.revoked,
    'client_status', v_rec.client_status));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_client: client row incl. allowed_origins/policy; registry:not_found
-- when absent (no existence leak — same code whether the id was never valid
-- or belongs to nobody the caller can see).
create or replace procedure registry.get_client(in pi_data jsonb, inout po_data jsonb)
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
    'allowed_origins', v_row.allowed_origins, 'policy', v_row.policy));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.list_intended_uses: every intended use registered for client_id.
-- An unknown client_id simply yields an empty list — this is a list read, not
-- a single-resource lookup, so there is no not_found case to distinguish.
create or replace procedure registry.list_intended_uses(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_items jsonb;
begin
  -- `id` is a tiebreaker, matching the sibling
  -- list procedures (list_filings/list_evidence: "order by created_at, id").
  -- Rows from the SAME insert/replace call (save_wrp_document,
  -- set_intended_uses) share one transaction's now() for created_at, so
  -- "order by created_at" ALONE is not just theoretically ambiguous but
  -- genuinely unstable across calls for those ties — this makes the result
  -- deterministic. It does NOT recover true insertion order for such ties
  -- (id is a ULID keyed on clock_timestamp() + random bits, so same-instant
  -- rows sort by their random suffix, not by loop order) — callers that need
  -- correctness independent of order (e.g. routes/filings.go's filing
  -- confirmation) must key by a stable identifier, never by this ordering.
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', iu.id, 'intended_use_id', iu.intended_use_id,
           'purpose', iu.purpose, 'credentials', iu.credentials,
           'revoked_at', iu.revoked_at
         ) order by iu.created_at, iu.id), '[]'::jsonb)
    into v_items
    from registry.intended_use iu
   where iu.client_id = pi_data->>'client_id';

  po_data := util.result_success(jsonb_build_object('intended_uses', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_intended_use: one row scoped to client_id; registry:not_found
-- when absent OR owned by another client (isolation happens via the WHERE,
-- not via a separate ownership check — no existence leak).
create or replace procedure registry.get_intended_use(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_row registry.intended_use%rowtype;
begin
  select * into v_row from registry.intended_use
   where client_id = pi_data->>'client_id' and intended_use_id = pi_data->>'intended_use_id';
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown intended use');
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'id', v_row.id, 'intended_use_id', v_row.intended_use_id,
    'purpose', v_row.purpose, 'credentials', v_row.credentials,
    'revoked_at', v_row.revoked_at));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_wrprc_for_intended_use: newest non-replaced, non-expired WRPRC
-- for (client_id, intended_use_id). TWO distinct absent cases, deliberately
-- NOT conflated:
--   1. intended use not owned by / unknown to this client -> registry:not_found
--      (404, no existence leak) — an ownership pre-check against
--      registry.intended_use, mirroring get_intended_use.
--   2. intended use IS owned but has no current WRPRC -> result_success('{}')
--      (a WRPRC is optional per Member State; absence is the
--      graceful registrar-reference fallback, never an error).
create or replace procedure registry.get_wrprc_for_intended_use(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_row   registry.wrprc%rowtype;
begin
  perform 1 from registry.intended_use
   where client_id = pi_data->>'client_id'
     and intended_use_id = pi_data->>'intended_use_id';

  if not found then
    po_data := util.result_error('registry:not_found', 'unknown intended use');
    return;
  end if;

  select * into v_row from registry.wrprc
   where client_id = pi_data->>'client_id'
     and intended_use_id = pi_data->>'intended_use_id'
     and replaced_at is null
     and (expires_at is null or expires_at > now())
   order by created_at desc
   limit 1;

  if not found then
    po_data := util.result_success('{}'::jsonb);
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'raw', encode(v_row.raw, 'base64'),
    'format', v_row.format,
    'expires_at', v_row.expires_at));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.create_template: Pattern A — validates the intended use exists for
-- THIS client and is not revoked before writing anything.
create or replace procedure registry.create_template(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_client_id       text := pi_data->>'client_id';
  v_intended_use_id text := pi_data->>'intended_use_id';
  v_revoked_at      date;
  v_id              text;
  v_created_at      timestamptz;
begin
  if v_client_id is null or pi_data->>'name' is null or v_intended_use_id is null
     or pi_data->'dcql_query' is null then
    po_data := util.result_error('registry:invalid', 'client_id, name, intended_use_id, dcql_query are required');
    return;
  end if;

  select revoked_at into v_revoked_at
    from registry.intended_use
   where client_id = v_client_id and intended_use_id = v_intended_use_id;

  if not found then
    po_data := util.result_error('registry:not_found', 'unknown intended use');
    return;
  end if;

  if v_revoked_at is not null then
    po_data := util.result_error('registry:intended_use_revoked', 'intended use has been revoked');
    return;
  end if;

  insert into registry.template (client_id, name, description, intended_use_id, dcql_query)
  values (v_client_id, pi_data->>'name', pi_data->>'description', v_intended_use_id, pi_data->'dcql_query')
  returning id, created_at into v_id, v_created_at;

  po_data := util.result_success(jsonb_build_object('id', v_id, 'created_at', v_created_at));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.get_template: soft-deleted or another client's template both read
-- as registry:not_found (no existence leak).
create or replace procedure registry.get_template(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_row registry.template%rowtype;
begin
  select * into v_row from registry.template
   where id = pi_data->>'template_id' and client_id = pi_data->>'client_id' and deleted_at is null;
  if not found then
    po_data := util.result_error('registry:not_found', 'unknown template');
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'id', v_row.id, 'name', v_row.name, 'description', v_row.description,
    'intended_use_id', v_row.intended_use_id, 'dcql_query', v_row.dcql_query,
    'created_at', v_row.created_at));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.list_templates: non-deleted templates owned by client_id.
create or replace procedure registry.list_templates(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_items jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', t.id, 'name', t.name, 'description', t.description,
           'intended_use_id', t.intended_use_id, 'dcql_query', t.dcql_query,
           'created_at', t.created_at
         ) order by t.created_at), '[]'::jsonb)
    into v_items
    from registry.template t
   where t.client_id = pi_data->>'client_id' and t.deleted_at is null;

  po_data := util.result_success(jsonb_build_object('templates', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.delete_template: soft delete. Pattern B — the UPDATE already ran
-- (matching zero rows is a no-op, nothing to physically roll back) but the
-- P0001 signal stays uniform with every other write procedure in this file.
-- Another client's template or an already-deleted one both read as
-- registry:not_found (no existence leak).
create or replace procedure registry.delete_template(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
begin
  update registry.template
     set deleted_at = now()
   where id = pi_data->>'template_id'
     and client_id = pi_data->>'client_id'
     and deleted_at is null;

  if not found then
    raise exception '%', util.result_error('registry:not_found', 'unknown template') using errcode = 'P0001';
  end if;

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.create_api_key: mints a new key row (secret hashing happens in Go —
-- this procedure only ever sees the argon2id PHC string).
create or replace procedure registry.create_api_key(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_id text;
begin
  if pi_data->>'client_id' is null or pi_data->>'prefix' is null or pi_data->>'secret_hash' is null then
    po_data := util.result_error('registry:invalid', 'client_id, prefix, secret_hash are required');
    return;
  end if;

  insert into registry.api_key (client_id, prefix, secret_hash)
  values (pi_data->>'client_id', pi_data->>'prefix', pi_data->>'secret_hash')
  returning id into v_id;

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when unique_violation then
    raise exception '%', util.result_error('registry:invalid', 'prefix already in use') using errcode = 'P0001';
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.revoke_api_key: Pattern B (see delete_template comment); another
-- client's key id reads as registry:not_found (no existence leak).
create or replace procedure registry.revoke_api_key(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
begin
  update registry.api_key
     set revoked_at = coalesce(revoked_at, now())
   where id = pi_data->>'key_id'
     and client_id = pi_data->>'client_id';

  if not found then
    raise exception '%', util.result_error('registry:not_found', 'unknown api key') using errcode = 'P0001';
  end if;

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.create_client: seed/test/onboarding primitive — the lifecycle
-- service owns the full lifecycle and adds lifecycle-guarded variants on top.
create or replace procedure registry.create_client(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_id text;
begin
  if pi_data->>'name' is null or pi_data->>'registry_uri' is null
     or pi_data->>'client_identifier' is null or pi_data->>'default_webhook_url' is null then
    po_data := util.result_error('registry:invalid',
      'name, registry_uri, client_identifier, default_webhook_url are required');
    return;
  end if;

  insert into registry.client (name, registry_uri, client_identifier, default_webhook_url, allowed_origins, policy)
  values (
    pi_data->>'name', pi_data->>'registry_uri', pi_data->>'client_identifier',
    pi_data->>'default_webhook_url',
    coalesce(pi_data->'allowed_origins', '[]'::jsonb),
    coalesce(pi_data->'policy', '{}'::jsonb))
  returning id into v_id;

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- registry.set_intended_uses: replace-all upsert — seed/test/onboarding
-- primitive (lifecycle-guarded variants live in the lifecycle service). Validates every
-- entry (Pattern A, no write yet) before upserting the supplied set and
-- deleting whatever this client had that is no longer present.
create or replace procedure registry.set_intended_uses(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = registry, util, pg_temp
as $$
declare
  v_client_id text := pi_data->>'client_id';
  v_item      jsonb;
  v_keep      text[] := '{}'::text[];
begin
  if v_client_id is null or pi_data->'intended_uses' is null then
    po_data := util.result_error('registry:invalid', 'client_id and intended_uses are required');
    return;
  end if;

  for v_item in select * from jsonb_array_elements(pi_data->'intended_uses')
  loop
    if v_item->>'intended_use_id' is null then
      po_data := util.result_error('registry:invalid', 'intended_use_id is required for every entry');
      return;
    end if;
    v_keep := array_append(v_keep, v_item->>'intended_use_id');
  end loop;

  for v_item in select * from jsonb_array_elements(pi_data->'intended_uses')
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

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('registry:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Lock down: EXECUTE only for the service role.
revoke all on procedure registry.get_client_by_key_prefix(jsonb, jsonb) from public;
revoke all on procedure registry.get_client(jsonb, jsonb) from public;
revoke all on procedure registry.list_intended_uses(jsonb, jsonb) from public;
revoke all on procedure registry.get_intended_use(jsonb, jsonb) from public;
revoke all on procedure registry.get_wrprc_for_intended_use(jsonb, jsonb) from public;
revoke all on procedure registry.create_template(jsonb, jsonb) from public;
revoke all on procedure registry.get_template(jsonb, jsonb) from public;
revoke all on procedure registry.list_templates(jsonb, jsonb) from public;
revoke all on procedure registry.delete_template(jsonb, jsonb) from public;
revoke all on procedure registry.create_api_key(jsonb, jsonb) from public;
revoke all on procedure registry.revoke_api_key(jsonb, jsonb) from public;
revoke all on procedure registry.create_client(jsonb, jsonb) from public;
revoke all on procedure registry.set_intended_uses(jsonb, jsonb) from public;

grant execute on procedure registry.get_client_by_key_prefix(jsonb, jsonb) to management_public;
grant execute on procedure registry.get_client(jsonb, jsonb) to management_public;
grant execute on procedure registry.list_intended_uses(jsonb, jsonb) to management_public;
grant execute on procedure registry.get_intended_use(jsonb, jsonb) to management_public;
grant execute on procedure registry.get_wrprc_for_intended_use(jsonb, jsonb) to management_public;
grant execute on procedure registry.create_template(jsonb, jsonb) to management_public;
grant execute on procedure registry.get_template(jsonb, jsonb) to management_public;
grant execute on procedure registry.list_templates(jsonb, jsonb) to management_public;
grant execute on procedure registry.delete_template(jsonb, jsonb) to management_public;
grant execute on procedure registry.create_api_key(jsonb, jsonb) to management_public;
grant execute on procedure registry.revoke_api_key(jsonb, jsonb) to management_public;
grant execute on procedure registry.create_client(jsonb, jsonb) to management_public;
grant execute on procedure registry.set_intended_uses(jsonb, jsonb) to management_public;

-- registration-api REUSES five of the procedures defined
-- above as-is: set_intended_uses (seed/onboarding upsert), create_api_key /
-- revoke_api_key (issuing keys once a client reaches 'active'),
-- get_client (legacy Client projection, predating the lifecycle columns),
-- and list_intended_uses — the
-- lifecycle service's "-> active" precondition ("at least one non-revoked
-- intended use") needs a read path onto the intended_use projections
-- registry.save_wrp_document writes, and this Store had none until this
-- grant + registrydb.Store.ListIntendedUses were added. Their grant lives
-- HERE, beside the definitions, rather than in
-- R__registry_registration_procedures.sql: that file used to
-- sort BEFORE this one in Evolve's ascending-filename ordering of repeatable
-- migrations, so a registration_api_public grant on these procedures placed
-- there would have failed with "procedure does not exist" on a from-zero
-- apply — see that file's footer comment; a later rename flipped the
-- ordering, but the grants stayed put beside their definitions regardless.
-- registration_api_public itself is created by util/V4, which applies before
-- any registry R__ file, so this grant always resolves. Re-asserting grants
-- in a repeatable migration is the house pattern.
grant execute on procedure registry.set_intended_uses(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.create_api_key(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.revoke_api_key(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.get_client(jsonb, jsonb) to registration_api_public;
grant execute on procedure registry.list_intended_uses(jsonb, jsonb) to registration_api_public;
