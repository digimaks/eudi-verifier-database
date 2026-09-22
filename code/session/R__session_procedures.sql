-- R: session procedures. SECURITY DEFINER, pinned search_path ending pg_temp,
-- JSONB envelope, Pattern A (pre-write) / Pattern B (post-write) errors.
-- Error codes: session:<reason>; the Go layer maps them onto the kit taxonomy
-- (err:session:<reason>) via errors.FromResultCode — ':not_found' → 404.

create or replace procedure session.create_session(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_id text;
begin
  if pi_data->>'client_id' is null or pi_data->>'correlation_id' is null
     or pi_data->>'flow' is null or pi_data->>'webhook_url' is null
     or pi_data->>'expires_at' is null then
    po_data := util.result_error('session:invalid', 'client_id, correlation_id, flow, webhook_url, expires_at are required');
    return;
  end if;

  -- id is optional: eudi-verifier-core passes the oid4vp engine's session id so
  -- ONE id names the session in Valkey, Postgres, and the wallet URL.
  insert into session.session (id, client_id, correlation_id, flow, policy, webhook_url, redirect_uri, expires_at)
  values (
    coalesce(pi_data->>'id', util.generate_ulid()),
    pi_data->>'client_id',
    pi_data->>'correlation_id',
    pi_data->>'flow',
    coalesce(pi_data->'policy', '{}'::jsonb),
    pi_data->>'webhook_url',
    pi_data->>'redirect_uri',
    (pi_data->>'expires_at')::timestamptz
  )
  returning id into v_id;

  po_data := util.result_success(jsonb_build_object('id', v_id));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

create or replace procedure session.get_session(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_row session.session%rowtype;
begin
  select * into v_row from session.session where id = pi_data->>'id';
  if not found then
    po_data := util.result_error('session:not_found', 'unknown session');
    return;
  end if;
  po_data := util.result_success(jsonb_build_object(
    'id', v_row.id, 'client_id', v_row.client_id, 'correlation_id', v_row.correlation_id,
    'flow', v_row.flow, 'status', v_row.status, 'policy', v_row.policy,
    'webhook_url', v_row.webhook_url, 'redirect_uri', v_row.redirect_uri,
    'expires_at', to_char(v_row.expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
  ));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

create or replace procedure session.set_status(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
begin
  update session.session
     set status = pi_data->>'status', updated_at = now()
   where id = pi_data->>'id';
  if not found then
    -- Pattern B: the UPDATE already ran (no-op) but semantics demand rollback signaling.
    raise exception '%', util.result_error('session:not_found', 'unknown session') using errcode = 'P0001';
  end if;
  po_data := util.result_success();
exception
  when check_violation then
    raise exception '%', util.result_error('session:invalid', 'invalid status value') using errcode = 'P0001';
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

create or replace procedure session.save_report(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_report_id text;
begin
  if pi_data->>'session_id' is null or pi_data->'report' is null then
    po_data := util.result_error('session:invalid', 'session_id and report are required');
    return;
  end if;
  insert into session.verification_report (session_id, report)
  values (pi_data->>'session_id', pi_data->'report')
  returning id into v_report_id;
  po_data := util.result_success(jsonb_build_object('id', v_report_id));
exception
  when foreign_key_violation then
    raise exception '%', util.result_error('session:not_found', 'unknown session') using errcode = 'P0001';
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.get_report: INTERNAL read (verifier_core_public) of the latest
-- verification report. A missing report here is treated as an anomaly ->
-- session:not_found. The client-facing sibling get_report_for_client
-- deliberately does the OPPOSITE for a report-less session (empty success
-- {}), since a pending session legitimately has none yet — any client-facing
-- endpoint MUST use that sibling, never this one.
create or replace procedure session.get_report(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_report jsonb;
begin
  select report into v_report
    from session.verification_report
   where session_id = pi_data->>'session_id'
   order by created_at desc limit 1;
  if not found then
    po_data := util.result_error('session:not_found', 'no report for session');
    return;
  end if;
  po_data := util.result_success(jsonb_build_object('report', v_report));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- Lock down: EXECUTE only for the service role.
revoke all on procedure session.create_session(jsonb, jsonb) from public;
revoke all on procedure session.get_session(jsonb, jsonb) from public;
revoke all on procedure session.set_status(jsonb, jsonb) from public;
revoke all on procedure session.save_report(jsonb, jsonb) from public;
revoke all on procedure session.get_report(jsonb, jsonb) from public;
grant execute on procedure session.create_session(jsonb, jsonb) to verifier_core_public;
grant execute on procedure session.get_session(jsonb, jsonb) to verifier_core_public;
grant execute on procedure session.set_status(jsonb, jsonb) to verifier_core_public;
grant execute on procedure session.save_report(jsonb, jsonb) to verifier_core_public;
grant execute on procedure session.get_report(jsonb, jsonb) to verifier_core_public;

-- management-api's client-scoped view of this schema. These
-- procedures are appended (repeatable migration — eudi-verifier-core's procedures
-- and grants above are untouched). management_public gets EXECUTE on exactly
-- the procedures below and nothing else: it never calls create_session or
-- save_report — those stay eudi-verifier-core-only (session ownership + report
-- writes happen inside the verification pipeline, not the client-facing API).

-- session.get_session_for_client: returns the row ONLY when client_id
-- matches (else session:not_found — no existence leak), lazily expiring a
-- pending/wallet_engaged session whose expires_at has passed before reading
-- it back (OID4VP session lifecycle; YAML Session.state enum).
create or replace procedure session.get_session_for_client(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_row session.session%rowtype;
begin
  update session.session
     set status = 'expired', updated_at = now()
   where id = pi_data->>'id'
     and client_id = pi_data->>'client_id'
     and status in ('pending', 'wallet_engaged')
     and expires_at <= now();

  select * into v_row from session.session
   where id = pi_data->>'id' and client_id = pi_data->>'client_id';

  if not found then
    po_data := util.result_error('session:not_found', 'unknown session');
    return;
  end if;

  po_data := util.result_success(jsonb_build_object(
    'id', v_row.id, 'client_id', v_row.client_id, 'correlation_id', v_row.correlation_id,
    'flow', v_row.flow, 'status', v_row.status, 'webhook_url', v_row.webhook_url,
    'redirect_uri', v_row.redirect_uri,
    'created_at', to_char(v_row.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'updated_at', to_char(v_row.updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'expires_at', to_char(v_row.expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'code_redeemed_at', case when v_row.code_redeemed_at is null then null
                              else to_char(v_row.code_redeemed_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') end,
    'webhook_state', v_row.webhook_state));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.cancel_session: transition matrix — allowed only from
-- pending/wallet_engaged (-> cancelled). Unknown id/wrong client and a
-- terminal-state session both fail with session:not_found /
-- session:not_cancellable respectively (the latter maps to err:session:not-
-- cancellable, 409, via the app.go "not-cancellable" reason registration).
-- A pending/wallet_engaged session already past expires_at is lazily expired
-- FIRST (fail-closed: it must end 'expired', never 'cancelled'), so the
-- cancellable check then sees a terminal state and returns not_cancellable —
-- keeping this in lockstep with get_session_for_client and the Go fake.
create or replace procedure session.cancel_session(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_status text;
begin
  update session.session
     set status = 'expired', updated_at = now()
   where id = pi_data->>'id'
     and client_id = pi_data->>'client_id'
     and status in ('pending', 'wallet_engaged')
     and expires_at <= now();

  select status into v_status from session.session
   where id = pi_data->>'id' and client_id = pi_data->>'client_id';

  if not found then
    po_data := util.result_error('session:not_found', 'unknown session');
    return;
  end if;

  if v_status not in ('pending', 'wallet_engaged') then
    po_data := util.result_error('session:not_cancellable', 'session is not in a cancellable state');
    return;
  end if;

  update session.session
     set status = 'cancelled', updated_at = now()
   where id = pi_data->>'id' and client_id = pi_data->>'client_id';

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.get_report_for_client: ownership check, then the newest report.
-- session:not_found is WRONG for "no report yet" — a pending session
-- legitimately has none, so that case returns empty success ({}), while a
-- verified session always has one.
create or replace procedure session.get_report_for_client(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_report jsonb;
begin
  perform 1 from session.session
   where id = pi_data->>'id' and client_id = pi_data->>'client_id';

  if not found then
    po_data := util.result_error('session:not_found', 'unknown session');
    return;
  end if;

  select report into v_report
    from session.verification_report
   where session_id = pi_data->>'id'
   order by created_at desc
   limit 1;

  if not found then
    po_data := util.result_success('{}'::jsonb);
    return;
  end if;

  po_data := util.result_success(jsonb_build_object('report', v_report));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.mark_code_redeemed: idempotent (coalesce keeps the first
-- timestamp), ownership-checked.
create or replace procedure session.mark_code_redeemed(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
begin
  update session.session
     set code_redeemed_at = coalesce(code_redeemed_at, now()), updated_at = now()
   where id = pi_data->>'id' and client_id = pi_data->>'client_id';

  if not found then
    raise exception '%', util.result_error('session:not_found', 'unknown session') using errcode = 'P0001';
  end if;

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.set_webhook_state: NO client scoping — this is the internal
-- webhook-consumer path, not client-facing. Pattern A validates the
-- state against the column's CHECK set before writing.
create or replace procedure session.set_webhook_state(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_state text := pi_data->>'state';
begin
  if v_state is null or v_state not in ('pending', 'delivering', 'delivered', 'failed') then
    po_data := util.result_error('session:invalid', 'state must be one of pending, delivering, delivered, failed');
    return;
  end if;

  update session.session
     set webhook_state = v_state,
         webhook_error = pi_data->>'error_code',
         updated_at = now()
   where id = pi_data->>'id';

  if not found then
    raise exception '%', util.result_error('session:not_found', 'unknown session') using errcode = 'P0001';
  end if;

  po_data := util.result_success();
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

-- session.expire_due_sessions: the sweeper's input. A single
-- statement (Go owns transaction scope, no commit here); FOR UPDATE SKIP
-- LOCKED lets multiple sweeper replicas run concurrently without contending
-- on the same rows.
create or replace procedure session.expire_due_sessions(in pi_data jsonb, inout po_data jsonb)
language plpgsql security definer
set search_path = session, util, pg_temp
as $$
declare
  v_limit int := coalesce((pi_data->>'limit')::int, 100);
  v_items jsonb;
begin
  with candidates as (
    select id from session.session
     where status in ('pending', 'wallet_engaged') and expires_at <= now()
     order by expires_at
     limit v_limit
     for update skip locked
  ),
  expired as (
    update session.session s
       set status = 'expired', updated_at = now()
      from candidates c
     where s.id = c.id
    returning s.id, s.client_id, s.webhook_url, s.correlation_id
  )
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', e.id, 'client_id', e.client_id,
           'webhook_url', e.webhook_url, 'correlation_id', e.correlation_id
         )), '[]'::jsonb)
    into v_items
    from expired e;

  po_data := util.result_success(jsonb_build_object('sessions', v_items));
exception
  when sqlstate 'P0001' then raise;
  when others then
    raise exception '%', util.result_error('session:error', sqlerrm) using errcode = 'P0001';
end;
$$;

revoke all on procedure session.get_session_for_client(jsonb, jsonb) from public;
revoke all on procedure session.cancel_session(jsonb, jsonb) from public;
revoke all on procedure session.get_report_for_client(jsonb, jsonb) from public;
revoke all on procedure session.mark_code_redeemed(jsonb, jsonb) from public;
revoke all on procedure session.set_webhook_state(jsonb, jsonb) from public;
revoke all on procedure session.expire_due_sessions(jsonb, jsonb) from public;

grant execute on procedure session.get_session_for_client(jsonb, jsonb) to management_public;
grant execute on procedure session.cancel_session(jsonb, jsonb) to management_public;
grant execute on procedure session.get_report_for_client(jsonb, jsonb) to management_public;
grant execute on procedure session.mark_code_redeemed(jsonb, jsonb) to management_public;
grant execute on procedure session.set_webhook_state(jsonb, jsonb) to management_public;
grant execute on procedure session.expire_due_sessions(jsonb, jsonb) to management_public;
