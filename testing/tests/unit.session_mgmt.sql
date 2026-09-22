-- SQL unit tests for the client-scoped session procedures appended to
-- session/R__session_procedures.sql (see unit.registry.sql for the plain
-- DO-block rationale).
--
-- Run as the owner (bypasses EXECUTE grants, so it can seed via
-- session.create_session AND drive the management-api-only procedures in one
-- script; the role boundary itself is covered by roleleak.sql):
--   psql "$DSN" \
--     -f testing/tests/unit.session_mgmt.sql
do $$
declare
  v jsonb;
begin
  ------------------------------------------------------------------
  -- Seed: an already-expired session and a still-pending one, both
  -- owned by client-unit-a (session.create_session is eudi-verifier-core-only
  -- in production; the owner role can call it here for test setup).
  ------------------------------------------------------------------
  v := null;
  call session.create_session(jsonb_build_object(
    'id', 'unittestexpiredsession001', 'client_id', 'client-unit-a',
    'correlation_id', 'corr-unit-exp', 'flow', 'cross_device',
    'webhook_url', 'https://a.example/hook', 'expires_at', (now() - interval '1 hour')), v);
  if v->>'result' is distinct from 'success' then raise exception 'seed expired session failed: %', v; end if;

  v := null;
  call session.create_session(jsonb_build_object(
    'id', 'unittestpendingsession001', 'client_id', 'client-unit-a',
    'correlation_id', 'corr-unit-pending', 'flow', 'cross_device',
    'webhook_url', 'https://a.example/hook', 'expires_at', (now() + interval '1 hour')), v);
  if v->>'result' is distinct from 'success' then raise exception 'seed pending session failed: %', v; end if;

  ------------------------------------------------------------------
  -- get_session_for_client: ownership + lazy expiry.
  ------------------------------------------------------------------
  -- wrong client on a still-pending session -> session:not_found (no
  -- existence leak: same code as a wholly unknown id).
  v := null;
  call session.get_session_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-b"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_found' then
    raise exception 'expected not_found for cross-client session read, got: %', v;
  end if;
  v := null;
  call session.get_session_for_client('{"id":"01JNOSUCHSESSION0000000000","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_found' then
    raise exception 'expected not_found for unknown session id, got: %', v;
  end if;

  -- own client, still-pending, not yet past expiry -> status unchanged
  v := null;
  call session.get_session_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_session_for_client failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'pending' then
    raise exception 'expected pending status before expiry, got: %', v;
  end if;

  -- own client, past expires_at, still 'pending' in the row -> lazily
  -- flips to 'expired' on this very read (OID4VP session lifecycle).
  v := null;
  call session.get_session_for_client('{"id":"unittestexpiredsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_session_for_client failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'expired' then
    raise exception 'expected lazy-expired status, got: %', v;
  end if;
  if v->'data'->>'webhook_state' is distinct from 'pending' then
    raise exception 'expected default webhook_state=pending, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- cancel_session: transition matrix.
  ------------------------------------------------------------------
  -- cross-client cancel -> not_found (Pattern A, before any write)
  v := null;
  call session.cancel_session('{"id":"unittestpendingsession001","client_id":"client-unit-b"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_found' then
    raise exception 'expected not_found for cross-client cancel, got: %', v;
  end if;

  -- pending -> cancelled succeeds
  v := null;
  call session.cancel_session('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'cancel (pending) failed: %', v; end if;
  v := null;
  call session.get_session_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_session_for_client failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'cancelled' then raise exception 'expected cancelled status, got: %', v; end if;

  -- cancelling a terminal-state (already cancelled) session -> not_cancellable
  v := null;
  call session.cancel_session('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_cancellable' then
    raise exception 'expected not_cancellable on a terminal-state session, got: %', v;
  end if;

  -- cancelling an already-expired session -> also not_cancellable (expired
  -- is terminal, same as cancelled/verified/failed)
  v := null;
  call session.cancel_session('{"id":"unittestexpiredsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_cancellable' then
    raise exception 'expected not_cancellable on an expired session, got: %', v;
  end if;

  -- Regression: a session STILL in the row as 'pending'
  -- (not yet swept) but already past expires_at must NOT be cancellable —
  -- cancel_session lazily expires it first, so it ends 'expired' (fail-closed,
  -- never 'cancelled') and the cancellable check returns not_cancellable.
  v := null;
  call session.create_session(jsonb_build_object(
    'id', 'unitteststalepending00001', 'client_id', 'client-unit-a',
    'correlation_id', 'corr-unit-stale', 'flow', 'cross_device',
    'webhook_url', 'https://a.example/hook', 'expires_at', (now() - interval '1 minute')), v);
  if v->>'result' is distinct from 'success' then raise exception 'seed stale-pending session failed: %', v; end if;
  v := null;
  call session.cancel_session('{"id":"unitteststalepending00001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_cancellable' then
    raise exception 'expected not_cancellable on a pending-past-expiry session, got: %', v;
  end if;
  v := null;
  call session.get_session_for_client('{"id":"unitteststalepending00001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_session_for_client failed: %', v; end if;
  if v->'data'->>'status' is distinct from 'expired' then
    raise exception 'expected pending-past-expiry session to end expired, not cancelled, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- get_report_for_client: ownership check + "no report yet" is success,
  -- not an error (a pending/cancelled session legitimately has none).
  ------------------------------------------------------------------
  v := null;
  call session.get_report_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-b"}'::jsonb, v);
  if v->>'code' is distinct from 'session:not_found' then
    raise exception 'expected not_found for cross-client report read, got: %', v;
  end if;
  v := null;
  call session.get_report_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' or v->'data' is distinct from '{}'::jsonb then
    raise exception 'expected empty success for a session with no report yet, got: %', v;
  end if;

  -- once a report exists (eudi-verifier-core writes it via session.save_report),
  -- get_report_for_client surfaces it.
  v := null;
  call session.save_report(jsonb_build_object(
    'session_id', 'unittestpendingsession001',
    'report', jsonb_build_object('outcome', 'verified', 'checks', '[]'::jsonb)), v);
  if v->>'result' is distinct from 'success' then raise exception 'save_report (seed) failed: %', v; end if;
  v := null;
  call session.get_report_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_report_for_client failed: %', v; end if;
  if v->'data'->'report'->>'outcome' is distinct from 'verified' then
    raise exception 'expected the seeded report to come back, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- mark_code_redeemed: ownership-checked, idempotent.
  ------------------------------------------------------------------
  begin
    v := null;
    call session.mark_code_redeemed('{"id":"unittestpendingsession001","client_id":"client-unit-b"}'::jsonb, v);
    raise exception 'expected P0001 for cross-client mark_code_redeemed';
  exception when sqlstate 'P0001' then
    if sqlerrm::jsonb->>'code' is distinct from 'session:not_found' then
      raise exception 'expected session:not_found, got: %', sqlerrm;
    end if;
  end;
  v := null;
  call session.mark_code_redeemed('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'mark_code_redeemed failed: %', v; end if;
  v := null;
  call session.get_session_for_client('{"id":"unittestpendingsession001","client_id":"client-unit-a"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'session.get_session_for_client failed: %', v; end if;
  if v->'data'->>'code_redeemed_at' is null then
    raise exception 'expected code_redeemed_at to be set, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- set_webhook_state: no client scoping (internal path); validates the
  -- state against the CHECK set (Pattern A).
  ------------------------------------------------------------------
  v := null;
  call session.set_webhook_state('{"id":"unittestpendingsession001","state":"delivering"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'set_webhook_state (delivering) failed: %', v; end if;
  v := null;
  call session.set_webhook_state('{"id":"unittestpendingsession001","state":"failed","error_code":"timeout"}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'set_webhook_state (failed) failed: %', v; end if;
  v := null;
  call session.set_webhook_state('{"id":"unittestpendingsession001","state":"not-a-state"}'::jsonb, v);
  if v->>'code' is distinct from 'session:invalid' then raise exception 'expected session:invalid, got: %', v; end if;
  begin
    v := null;
    call session.set_webhook_state('{"id":"01JNOSUCHSESSION0000000000","state":"pending"}'::jsonb, v);
    raise exception 'expected P0001 for unknown session in set_webhook_state';
  exception when sqlstate 'P0001' then
    if sqlerrm::jsonb->>'code' is distinct from 'session:not_found' then
      raise exception 'expected session:not_found, got: %', sqlerrm;
    end if;
  end;

  ------------------------------------------------------------------
  -- expire_due_sessions: the sweeper's input. The already-expired seed
  -- session was lazily flipped to 'expired' by get_session_for_client
  -- above, so it must NOT be picked up again (status filter excludes it);
  -- seed a fresh due-but-still-pending session to prove the sweep itself.
  ------------------------------------------------------------------
  v := null;
  call session.create_session(jsonb_build_object(
    'id', 'unittestsweepduesession01', 'client_id', 'client-unit-a',
    'correlation_id', 'corr-unit-sweep', 'flow', 'same_device',
    'webhook_url', 'https://a.example/hook', 'expires_at', (now() - interval '1 minute')), v);
  if v->>'result' is distinct from 'success' then raise exception 'seed sweep-due session failed: %', v; end if;

  v := null;
  call session.expire_due_sessions('{"limit":100}'::jsonb, v);
  if v->>'result' is distinct from 'success' then raise exception 'expire_due_sessions failed: %', v; end if;
  if not exists (
    select 1 from jsonb_array_elements(v->'data'->'sessions') s
     where s->>'id' = 'unittestsweepduesession01'
  ) then
    raise exception 'expected unittestsweepduesession01 in the swept batch, got: %', v;
  end if;
  if exists (
    select 1 from jsonb_array_elements(v->'data'->'sessions') s
     where s->>'id' = 'unittestexpiredsession001'
  ) then
    raise exception 'did not expect the already-lazily-expired session to be re-swept: %', v;
  end if;

  raise notice 'unit.session_mgmt.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.session_mgmt.sql: PASS' as result;
