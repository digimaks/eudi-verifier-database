-- management-api projections on eudi-verifier-core's session schema.
-- Additive only; eudi-verifier-core's procedures/rows are untouched.
alter table session.session add column if not exists code_redeemed_at timestamptz;
alter table session.session add column if not exists webhook_state text not null default 'pending'
  check (webhook_state in ('pending','delivering','delivered','failed'));
alter table session.session add column if not exists webhook_error text;

grant usage on schema session to management_public;
