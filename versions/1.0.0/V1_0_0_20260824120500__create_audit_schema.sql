create schema if not exists audit;

create table if not exists audit.entry (
  id         text primary key default util.generate_ulid(),
  at         timestamptz not null default now(),
  actor      text not null,          -- operator/client-user id or 'system:ts5-job' etc.
  client_id  text,
  action     text not null,          -- e.g. 'client.transition', 'evidence.add'
  detail     jsonb not null default '{}'::jsonb
);

-- ARF TS7 deletion-request log (ARF AS-RP-48-004): timestamp, RP, attribute NAMES
-- only — never values.
create table if not exists audit.deletion_request (
  id              text primary key default util.generate_ulid(),
  client_id       text not null,
  session_id      text not null,     -- digimaks session that authenticated the requester
  attribute_names jsonb not null,    -- names only
  requested_at    timestamptz not null default now()
);

-- Append-only enforcement: revoke + guard trigger.
create or replace function audit.block_mutation() returns trigger
language plpgsql as $$
begin
  raise exception 'audit schema is append-only';
end $$;
drop trigger if exists entry_no_mutation on audit.entry;
create trigger entry_no_mutation before update or delete on audit.entry
  for each row execute function audit.block_mutation();
drop trigger if exists deletion_request_no_mutation on audit.deletion_request;
create trigger deletion_request_no_mutation before update or delete on audit.deletion_request
  for each row execute function audit.block_mutation();

revoke all on schema audit from public;
revoke all on all tables in schema audit from public;
grant usage on schema audit to registration_api_public;
grant usage on schema audit to management_public;  -- future: mgmt reads its own audit views (none today)
