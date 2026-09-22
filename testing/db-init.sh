#!/bin/sh
# Prepare a database for LOCAL / CI testing + PL/pgSQL static analysis.
#
# Runs a psql CLIENT — so it works BOTH ways:
#   * ON the DB server/VM: copy this repo, set DB_HOST=localhost (or leave it —
#     falls back to POSTGRES_HOST), run `sh testing/db-init.sh`.
#   * from a client image (e.g. tmaier/postgresql-client) against a remote server
#     (the digimaks CI pattern: wait-for-postgres.sh then db-init.sh).
#
# Connection/identity come ENTIRELY from the environment — no hardcoded DB name or
# owner (same script for any deployment name):
#   DB_HOST (falls back to POSTGRES_HOST; required) · DB_PORT (default 5432) ·
#   POSTGRES_USER / POSTGRES_DB / POSTGRES_PASSWORD · ON_ERROR_STOP (default ON) ·
#   *_PUBLIC_PW  (per-role passwords consumed by provision-roles.sh)
#
# NOT used by production/runtime — the live stack brings the DB up via
# provision-roles.sh + the migrations directly. This is the dev/CI convenience.
set -e
DIR=$(dirname "$0")

if [ -z "${DB_PORT:-}" ]; then DB_PORT=5432; fi
if [ -z "${DB_HOST:-}" ]; then
  if [ -z "${POSTGRES_HOST:-}" ]; then
    echo "DB_HOST is not set (and POSTGRES_HOST is empty)" >&2
    exit 1
  fi
  DB_HOST=$POSTGRES_HOST
fi
export PGPASSWORD=${POSTGRES_PASSWORD:-}
if [ -z "${ON_ERROR_STOP:-}" ]; then ON_ERROR_STOP=ON; fi

# 1. Service roles — created from the environment. Secret-free replacement for the
#    old init.sql inline-password role creation (no credentials in the tree).
echo "INIT: provisioning EXECUTE-only service roles from the environment"
PGHOST="$DB_HOST" PGPORT="$DB_PORT" PGUSER="$POSTGRES_USER" PGDATABASE="$POSTGRES_DB" \
  sh "$DIR/provision-roles.sh"

# 2. plpgsql_check — the PL/pgSQL static-analysis extension lint-pgSQL.sql uses.
#    Non-trusted and NOT bundled in a stock postgres image → the SERVER must be a
#    postgres image/build that ships it. The RUNTIME extension (pgcrypto) is
#    installed by the util migration, not here. Migrations run separately (Evolve).
echo "INIT: installing plpgsql_check"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP="$ON_ERROR_STOP" -c 'CREATE EXTENSION IF NOT EXISTS plpgsql_check;'

echo "db-init: complete"
