-- V1: util schema — shared primitives.
create schema if not exists util;

-- pgcrypto supplies gen_random_bytes (used by generate_ulid). Install it into
-- util (standalone digimaks DB) so it sits on every procedure's pinned
-- search_path; if the extension already exists elsewhere (e.g. public in a
-- shared platform-DB co-deployment) this is a harmless no-op and
-- generate_ulid's own search_path (below) still resolves it via public.
create extension if not exists pgcrypto with schema util;

-- ULID: 48-bit ms timestamp + 80 random bits, Crockford base32.
-- Pinned search_path (util first, public as co-deploy fallback, pg_temp last):
-- self-contained so gen_random_bytes resolves regardless of the caller's path.
create or replace function util.generate_ulid() returns text
language plpgsql volatile
set search_path = util, public, pg_temp
as $$
declare
  encoding   text := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  ts         bigint := floor(extract(epoch from clock_timestamp()) * 1000);
  output     text := '';
  rand_bytes bytea := gen_random_bytes(10);
  acc        bigint := 0;   -- 5-bit encoder accumulator for the 80 random bits
  nbits      int := 0;      -- bits currently buffered in acc
begin
  -- 48-bit timestamp → 10 Crockford base32 chars.
  for i in reverse 9..0 loop
    output := output || substr(encoding, ((ts >> (i * 5)) & 31)::int + 1, 1);
  end loop;
  -- 80-bit randomness → 16 chars: feed each byte in and drain 5 bits at a time
  -- (80 / 5 = 16 exactly). Masking off consumed high bits keeps acc within
  -- bigint range (a plain get_byte & 31 per byte would emit only 10 chars →
  -- a 20-char, non-canonical id).
  for i in 0..9 loop
    acc   := (acc << 8) | get_byte(rand_bytes, i);
    nbits := nbits + 8;
    while nbits >= 5 loop
      nbits  := nbits - 5;
      output := output || substr(encoding, ((acc >> nbits) & 31)::int + 1, 1);
    end loop;
    acc := acc & ((1 << nbits) - 1);
  end loop;
  return output;   -- 10 + 16 = 26 chars (canonical ULID length)
end;
$$;

create or replace function util.result_success(p_data jsonb default '{}'::jsonb) returns jsonb
language sql immutable
as $$ select jsonb_build_object('result', 'success', 'data', p_data) $$;

create or replace function util.result_error(p_code text, p_message text default null) returns jsonb
language sql immutable
as $$ select jsonb_build_object('result', 'error', 'code', p_code, 'message', p_message) $$;
