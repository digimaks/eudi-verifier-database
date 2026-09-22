-- SQL unit tests for the audit schema (audit/V1 tables +
-- audit/R__audit_procedures.sql) — see unit.registry.sql for the plain
-- DO-block rationale.
--
-- Run as the owner (bypasses EXECUTE grants and the append-only guard
-- applies regardless of role — even the owner cannot UPDATE/DELETE; the
-- registration_api_public-specific role-boundary is covered separately by
-- roleleak.sql):
--   psql "$DSN" \
--     -f testing/tests/unit.audit.sql
do $$
declare
  v         jsonb;
  v_id      text;
  v_client  text := '01JUNITAUDITCLIENT00000000';
begin
  ------------------------------------------------------------------
  -- audit.append: happy path + required-field validation.
  ------------------------------------------------------------------
  v := null;
  call audit.append(jsonb_build_object(
    'actor', 'unit-test', 'client_id', v_client, 'action', 'unit.append.test',
    'detail', jsonb_build_object('note', 'hello')), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.append failed: %', v; end if;
  v_id := v->'data'->>'id';
  if length(v_id) is distinct from 26 then raise exception 'expected a 26-char ULID for the audit entry, got: %', v_id; end if;

  v := null;
  call audit.append('{"actor":"unit-test"}'::jsonb, v);
  if v->>'code' is distinct from 'audit:invalid' then raise exception 'expected audit:invalid for a missing action, got: %', v; end if;

  -- client_id is nullable: an operator-scoped entry with no client still
  -- succeeds.
  v := null;
  call audit.append(jsonb_build_object('actor', 'unit-test', 'action', 'operator.login'), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.append (no client_id) failed: %', v; end if;

  if not exists (select 1 from audit.entry where id = v_id and detail->>'note' = 'hello') then
    raise exception 'expected the appended entry to be readable back with its detail intact';
  end if;

  ------------------------------------------------------------------
  -- Append-only enforcement: UPDATE/DELETE on
  -- audit.entry raise the guard trigger's exception, even for the owner —
  -- the trigger fires regardless of role.
  ------------------------------------------------------------------
  begin
    update audit.entry set action = 'tampered' where id = v_id;
    raise exception 'expected audit.entry UPDATE to be blocked by the append-only guard';
  exception when others then
    if sqlerrm not like '%append-only%' then
      raise exception 'expected the append-only guard message, got: %', sqlerrm;
    end if;
  end;

  begin
    delete from audit.entry where id = v_id;
    raise exception 'expected audit.entry DELETE to be blocked by the append-only guard';
  exception when others then
    if sqlerrm not like '%append-only%' then
      raise exception 'expected the append-only guard message, got: %', sqlerrm;
    end if;
  end;

  if not exists (select 1 from audit.entry where id = v_id and action = 'unit.append.test') then
    raise exception 'expected the entry to be UNCHANGED after the blocked UPDATE/DELETE attempts';
  end if;

  ------------------------------------------------------------------
  -- audit.list_entries: newest-first, scoped to client_id —
  -- the operator client-detail page's "audit trail visible" read path.
  ------------------------------------------------------------------
  v := null;
  call audit.append(jsonb_build_object(
    'actor', 'unit-test', 'client_id', v_client, 'action', 'unit.list_entries.second'), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.append (second entry) failed: %', v; end if;

  v := null;
  call audit.list_entries(jsonb_build_object('client_id', v_client, 'limit', 10), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.list_entries failed: %', v; end if;
  -- exactly the two v_client-scoped entries appended above (the no-client_id
  -- 'operator.login' entry above must NOT appear: it has client_id = null).
  if jsonb_array_length(v->'data'->'entries') is distinct from 2 then
    raise exception 'expected exactly 2 audit entries for client %, got: %', v_client, v;
  end if;
  -- newest first: 'unit.list_entries.second' was appended after
  -- 'unit.append.test', so it must be entries[0].
  if v->'data'->'entries'->0->>'action' is distinct from 'unit.list_entries.second' then
    raise exception 'expected the most recently appended entry first, got: %', v;
  end if;
  if v->'data'->'entries'->1->>'action' is distinct from 'unit.append.test' then
    raise exception 'expected the earlier entry second, got: %', v;
  end if;

  -- another client sees none of it (list is scoped, not global).
  v := null;
  call audit.list_entries(jsonb_build_object('client_id', 'some-other-client', 'limit', 10), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.list_entries failed: %', v; end if;
  if v->'data'->'entries' is distinct from '[]'::jsonb then
    raise exception 'expected no entries for an unrelated client, got: %', v;
  end if;

  ------------------------------------------------------------------
  -- audit.log_deletion_request / audit.list_deletion_requests: ARF TS7
  -- deletion-request log (ARF AS-RP-48-004) — attribute NAMES only.
  ------------------------------------------------------------------
  v := null;
  call audit.log_deletion_request(jsonb_build_object(
    'client_id', v_client, 'session_id', 'sess-unit-1',
    'attribute_names', jsonb_build_array('given_name', 'family_name')), v);
  if v->>'result' is distinct from 'success' then raise exception 'log_deletion_request failed: %', v; end if;

  v := null;
  call audit.log_deletion_request(jsonb_build_object('client_id', v_client, 'session_id', 'sess-unit-2'), v);
  if v->>'code' is distinct from 'audit:invalid' then
    raise exception 'expected audit:invalid for a missing attribute_names, got: %', v;
  end if;

  v := null;
  call audit.list_deletion_requests(jsonb_build_object('client_id', v_client, 'limit', 10), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.list_deletion_requests failed: %', v; end if;
  if jsonb_array_length(v->'data'->'requests') is distinct from 1 then
    raise exception 'expected exactly 1 deletion request for client %, got: %', v_client, v;
  end if;
  if v->'data'->'requests'->0->'attribute_names' is distinct from '["given_name", "family_name"]'::jsonb then
    raise exception 'expected the attribute NAMES to round-trip verbatim, got: %', v;
  end if;

  -- another client sees none of it (list is scoped, not global).
  v := null;
  call audit.list_deletion_requests(jsonb_build_object('client_id', 'some-other-client', 'limit', 10), v);
  if v->>'result' is distinct from 'success' then raise exception 'audit.list_deletion_requests failed: %', v; end if;
  if v->'data'->'requests' is distinct from '[]'::jsonb then
    raise exception 'expected no deletion requests for an unrelated client, got: %', v;
  end if;

  -- Append-only guard also covers audit.deletion_request.
  begin
    update audit.deletion_request set session_id = 'tampered' where client_id = v_client;
    raise exception 'expected audit.deletion_request UPDATE to be blocked by the append-only guard';
  exception when others then
    if sqlerrm not like '%append-only%' then
      raise exception 'expected the append-only guard message, got: %', sqlerrm;
    end if;
  end;

  raise notice 'unit.audit.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.audit.sql: PASS' as result;
