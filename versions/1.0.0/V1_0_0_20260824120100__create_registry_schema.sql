-- registry schema: clients, intended uses, templates, WRPRC refs.
-- Legal-entity data only — never attribute values. Later migrations extend
-- this schema (lifecycle, filings, evidence) with
-- registry/V2+; procedures live in R__registry_procedures.sql.
create schema if not exists registry;

create table if not exists registry.client (
  id                  text primary key default util.generate_ulid(),
  name                text not null,
  -- Named constraint: the V2 migration replaces it with the full 7-state
  -- lifecycle set (that migration depends on this exact name).
  status              text not null default 'active'
                      constraint client_status_check
                      check (status in ('active','suspended','offboarded')),
  registry_uri        text not null,
  client_identifier   text not null,             -- registrar-assigned WRP identifier (ARF TS5 `sub`)
  default_webhook_url text not null,
  allowed_origins     jsonb not null default '[]'::jsonb,
  policy              jsonb not null default '{}'::jsonb,  -- policy.ClientPolicy snapshot source
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

create table if not exists registry.intended_use (
  id              text primary key default util.generate_ulid(),
  client_id       text not null references registry.client (id),
  intended_use_id text not null,                 -- registrar-assigned intendedUseIdentifier (ARF TS5)
  purpose         jsonb not null default '[]'::jsonb,
  credentials     jsonb not null default '[]'::jsonb, -- []RegisteredCredentialJSON (dcql.WithinScope input)
  revoked_at      date,
  created_at      timestamptz not null default now(),
  unique (client_id, intended_use_id)
);

create table if not exists registry.template (
  id              text primary key default util.generate_ulid(),
  client_id       text not null references registry.client (id),
  name            text not null,
  description     text,
  intended_use_id text not null,
  dcql_query      jsonb not null,
  created_at      timestamptz not null default now(),
  deleted_at      timestamptz
);
create index if not exists template_client_idx on registry.template (client_id) where deleted_at is null;

create table if not exists registry.api_key (
  id          text primary key default util.generate_ulid(),
  client_id   text not null references registry.client (id),
  prefix      text not null unique,              -- public lookup id (never secret-derived)
  secret_hash text not null,                     -- argon2id PHC string
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz,
  last_used_at timestamptz
);

create table if not exists registry.wrprc (
  id              text primary key default util.generate_ulid(),
  client_id       text not null references registry.client (id),
  intended_use_id text not null,
  raw             bytea not null,                -- verbatim signed WRPRC (JWT/CWT bytes)
  format          text not null check (format in ('jwt','cwt')),
  expires_at      timestamptz,                   -- null = no exp claim
  created_at      timestamptz not null default now(),
  replaced_at     timestamptz
);
create index if not exists wrprc_lookup_idx on registry.wrprc (client_id, intended_use_id) where replaced_at is null;

revoke all on schema registry from public;
revoke all on all tables in schema registry from public;
grant usage on schema registry to management_public;
grant usage on schema util to management_public;
-- NO table/sequence grants — EXECUTE-only.
-- Procedure EXECUTE grants live in R__registry_procedures.sql.
