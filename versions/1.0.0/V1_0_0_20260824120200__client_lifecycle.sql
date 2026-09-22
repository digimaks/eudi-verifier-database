-- Full client lifecycle + onboarding artifacts.
-- Widens the status CHECK to the full state machine (7 states).
alter table registry.client drop constraint if exists client_status_check;
alter table registry.client add constraint client_status_check check (status in
  ('draft','evidence_submitted','filed_with_registrar','registered','active','suspended','offboarded'));
alter table registry.client alter column status set default 'draft';
alter table registry.client add column if not exists slug text unique;
alter table registry.client add column if not exists wrp_document jsonb;      -- full ARF TS6 doc (source of truth; intended_use rows are projections)
alter table registry.client add column if not exists contact_emails jsonb not null default '[]'::jsonb;

create table if not exists registry.evidence (
  id          text primary key default util.generate_ulid(),
  client_id   text not null references registry.client (id),
  filename    text not null,
  mime        text not null,
  size_bytes  bigint not null check (size_bytes > 0 and size_bytes <= 10485760), -- 10 MiB cap
  sha256      text not null,
  content     bytea not null,
  uploaded_by text not null,
  created_at  timestamptz not null default now()
);

grant usage on schema registry to registration_api_public;
grant usage on schema util to registration_api_public;
-- EXECUTE-only: procedure grants in R__registry_registration_procedures.sql.
