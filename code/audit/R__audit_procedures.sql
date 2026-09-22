-- audit-schema procedures.
-- registration_api_public is the only caller. audit.entry/audit.deletion_request
-- are append-only (V1's guard triggers) — these procedures only ever
-- INSERT/SELECT, never UPDATE/DELETE. No attribute VALUES ever land here:
-- audit.deletion_request stores attribute NAMES only.

-- audit.append: generic audit-trail write. actor is an operator/client-user
-- id, or a fixed 'system:<job>' string for background jobs — the caller
-- decides; this procedure does not validate its shape beyond non-null.
-- client_id is nullable (some entries, e.g. operator login, are not
-- client-scoped).
create or replace procedure audit.append(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = audit, util, pg_temp
as $$
declare
  v_id text;
begin
  if pi_data->>'actor' is null or pi_data->>'action' is null then
    po_data := util.result_error('audit:invalid', 'actor and action are required');
    return;
  end if;

  insert into audit.entry (actor, client_id, action, detail)
  values (pi_data->>'actor', pi_data->>'client_id', pi_data->>'action',
          coalesce(pi_data->'detail', '{}'::jsonb))
  returning id into v_id;

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('audit:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- audit.list_entries: general-purpose audit-trail read for one client,
-- newest first — audit.append/the atomic-write procedures had no matching
-- read path, and the operator client-detail page's audit trail needs
-- one. Same envelope/ordering idiom as list_deletion_requests below.
create or replace procedure audit.list_entries(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = audit, util, pg_temp
as $$
declare
  v_limit int := coalesce((pi_data->>'limit')::int, 100);
  v_items jsonb;
begin
  -- at ties (possible: several rows written in the same transaction, e.g.
  -- transition_client's flip + its own audit insert share now()) are broken
  -- by id — ULIDs embed a creation-time prefix, so "newest first" stays
  -- deterministic instead of an arbitrary tie order.
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', e.id, 'at', e.at, 'actor', e.actor, 'client_id', e.client_id,
           'action', e.action, 'detail', e.detail
         ) order by e.at desc, e.id desc), '[]'::jsonb)
    into v_items
    from (
      select * from audit.entry
       where client_id = pi_data->>'client_id'
       order by at desc, id desc
       limit v_limit
    ) e;

  po_data := util.result_success(jsonb_build_object('entries', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('audit:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- audit.log_deletion_request: ARF TS7 deletion-request log (ARF AS-RP-48-004).
-- attribute_names MUST be a JSON array of claim/attribute NAMES — never
-- values. The caller (registrydb.Store.LogDeletionRequest) is the
-- single chokepoint that enforces this; the procedure itself only checks
-- presence, not content, since it has no way to distinguish a name from a
-- value string.
create or replace procedure audit.log_deletion_request(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = audit, util, pg_temp
as $$
declare
  v_id text;
begin
  if pi_data->>'client_id' is null or pi_data->>'session_id' is null
     or pi_data->'attribute_names' is null then
    po_data := util.result_error('audit:invalid', 'client_id, session_id, attribute_names are required');
    return;
  end if;

  insert into audit.deletion_request (client_id, session_id, attribute_names)
  values (pi_data->>'client_id', pi_data->>'session_id', pi_data->'attribute_names')
  returning id into v_id;

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('audit:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- audit.list_deletion_requests: newest first, scoped to client_id (compliance
-- endpoint + operator dashboard read).
create or replace procedure audit.list_deletion_requests(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = audit, util, pg_temp
as $$
declare
  v_limit int := coalesce((pi_data->>'limit')::int, 100);
  v_items jsonb;
begin
  -- requested_at ties (possible: now() is frozen for a whole transaction)
  -- are broken by id — ULIDs embed a creation-time prefix, so "newest
  -- first" stays deterministic instead of an arbitrary tie order.
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', d.id, 'client_id', d.client_id, 'session_id', d.session_id,
           'attribute_names', d.attribute_names, 'requested_at', d.requested_at
         ) order by d.requested_at desc, d.id desc), '[]'::jsonb)
    into v_items
    from (
      select * from audit.deletion_request
       where client_id = pi_data->>'client_id'
       order by requested_at desc, id desc
       limit v_limit
    ) d;

  po_data := util.result_success(jsonb_build_object('requests', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('audit:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Lock down: EXECUTE only for the service role.
revoke all on procedure audit.append(jsonb, jsonb) from public;
revoke all on procedure audit.list_entries(jsonb, jsonb) from public;
revoke all on procedure audit.log_deletion_request(jsonb, jsonb) from public;
revoke all on procedure audit.list_deletion_requests(jsonb, jsonb) from public;

grant execute on procedure audit.append(jsonb, jsonb) to registration_api_public;
grant execute on procedure audit.list_entries(jsonb, jsonb) to registration_api_public;
grant execute on procedure audit.log_deletion_request(jsonb, jsonb) to registration_api_public;
grant execute on procedure audit.list_deletion_requests(jsonb, jsonb) to registration_api_public;
