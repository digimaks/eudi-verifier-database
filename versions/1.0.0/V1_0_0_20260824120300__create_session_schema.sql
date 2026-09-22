-- V1: session schema — session metadata + verification reports.
-- Claim NAMES only, never values. Tables unreachable by
-- service roles; access via SECURITY DEFINER procedures in R__ only.
create schema if not exists session;

create table if not exists session.session (
  id             text primary key default util.generate_ulid(),
  client_id      text not null,
  correlation_id text not null,
  flow           text not null
                 check (flow in ('same_device', 'cross_device', 'dcapi')),
  status         text not null default 'pending'
                 check (status in ('pending', 'wallet_engaged', 'verified', 'failed', 'expired', 'cancelled')),
  policy         jsonb not null default '{}'::jsonb,   -- per-client policy snapshot
  webhook_url    text not null,
  redirect_uri   text,                                  -- same-device client return target
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  expires_at     timestamptz not null
);

create table if not exists session.verification_report (
  id         text primary key default util.generate_ulid(),
  session_id text not null references session.session (id),
  report     jsonb not null,   -- CheckResults + claim names ONLY
  created_at timestamptz not null default now()
);

create index if not exists verification_report_session_idx
  on session.verification_report (session_id);

grant usage on schema session to verifier_core_public;
grant usage on schema util to verifier_core_public;
-- NO table/sequence grants — EXECUTE-only.
