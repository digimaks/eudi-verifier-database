#!/bin/sh
# Provision the per-service EXECUTE-only Postgres roles from the environment.
#
# Lives in the DB repo (not the deployment glue) so the repo is a self-contained
# bring-up: create roles -> migrate, all in one place, deployable by anyone.
#
# Why roles are created here (not in a versioned migration): a role's *credentials*
# are an operational concern, not a schema one. The migrations therefore only
# assign privileges (GRANT EXECUTE / REVOKE FROM PUBLIC); this one-shot creates the
# roles with passwords sourced from the environment and MUST run BEFORE migrate.
# Result: versioned migrations carry zero credentials, and the same env var feeds
# both the role password here AND the service DSN (single source, cannot drift).
# In production this step reads from Vault/KMS.
#
# Idempotent: create a role if absent, else re-apply its password (rotation on the
# next run). Connects as the DB owner/superuser via the PG* env vars.
set -eu

# "<role>:<env-var-holding-its-password>" — one entry per service role.
# NOTE: env-var name and role name differ where the source .env named them so
# (management_public <- MANAGEMENT_API_PUBLIC_PW, etc.).
ROLES="verifier_core_public:VERIFIER_CORE_PUBLIC_PW \
management_public:MANAGEMENT_API_PUBLIC_PW \
registration_api_public:REGISTRATION_API_PUBLIC_PW"

for entry in $ROLES; do
  role="${entry%%:*}"
  var="${entry#*:}"
  eval "pw=\${$var:-}"
  [ -n "$pw" ] || { echo "FATAL: \$$var is empty -- set it in the environment" >&2; exit 1; }
  if psql -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_roles WHERE rolname='$role'" | grep -q 1; then
    psql -v ON_ERROR_STOP=1 -c "ALTER ROLE \"$role\" WITH LOGIN PASSWORD '$pw'"
    echo "  role $role: password synced"
  else
    psql -v ON_ERROR_STOP=1 -c "CREATE ROLE \"$role\" LOGIN PASSWORD '$pw'"
    echo "  role $role: created"
  fi
done
echo "pg-roles: provisioning complete"
