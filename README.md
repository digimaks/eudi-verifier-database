# verifier-database

The PostgreSQL data layer of the **EUDI wallet verifier** — one database, a schema per
domain, authored as [Evolve](https://evolve-db.netlify.app/) migrations. The SQL is not
tied to that tool: the files are plain SQL under a naming convention, so any runner that
applies the versioned files in order and then the repeatable ones applies this set.
**Evolve and [Flyway](https://https://www.red-gate.com/products/flyway/) both do**, and both are shown below.

The migration set is **database-name and owner-name free** — connection and identity come
entirely from the environment, so the same files deploy under any database name or owner
(dev, CI, or a named production database) with no SQL edits. Services never touch tables:
every schema is consumed only through its `SECURITY DEFINER` procedures, and each
consuming service decides which procedures it calls.

## Layout

```
versions/1.0.0/   V*.sql     versioned migrations — applied once, checksummed
code/<schema>/    R__*.sql   procedure definitions — re-applied whenever they change
testing/                     bring-up, SQL unit tests, static analysis
```

Versioned migrations carry a globally unique version:

```
V<major>_<minor>_<patch>_<yyyymmddhhmmss>__<description>.sql
```

which sorts by release and then by authoring time, so two people cannot mint the same
version from different branches. The runner keeps **one** history table for the whole
set.

## Running the migrations

### Generate the passwords

Four passwords are needed: one for the database owner (`verifier` in the examples below —
any name works) and one per service role. Generate each by running this in a bash shell,
once per password:

```sh
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; echo
```

| Password for | Used by |
| :-- | :-- |
| `verifier` (owner) | the database owner, and the identity migrations run as |
| `verifier_core_public` | role `verifier_core_public` — and later that service's DSN |
| `management_public` | role `management_public` — and later that service's DSN |
| `registration_api_public` | role `registration_api_public` — and later that service's DSN |

> Keep all four somewhere safe. The three role passwords are **reused** when the services'
> database connections are configured — they must match exactly. They are alphanumeric on
> purpose: nothing in them can break a connection string or an SQL statement.

### Create the database roles

Roles are created **outside** the migrations, because a credential is an operational
concern and a schema is not. The migrations only assign privileges, and only to roles that
already exist — a missing role fails the migration rather than silently leaving a schema
unreachable.

From the environment, which is what CI and local bring-up use:

```sh
export POSTGRES_HOST=localhost POSTGRES_USER=verifier POSTGRES_DB=verifier
export POSTGRES_PASSWORD=...            # the owner password
export VERIFIER_CORE_PUBLIC_PW=...      # one per service role
export MANAGEMENT_API_PUBLIC_PW=...
export REGISTRATION_API_PUBLIC_PW=...

sh testing/provision-roles.sh
```

It is idempotent: a role that exists has its password re-applied, which is also how a
rotation lands. On a real deployment the same script runs with the passwords coming from
the secret store, before the first migration.

By hand, the equivalent is three statements:

```sql
CREATE ROLE verifier_core_public    LOGIN PASSWORD '...';
CREATE ROLE management_public       LOGIN PASSWORD '...';
CREATE ROLE registration_api_public LOGIN PASSWORD '...';
```

### Verify

List the roles:

```sh
psql -U verifier -d verifier -c "\du"
```

Expect the three `*_public` roles each with a **blank Attributes column** — that is
correct. `psql` prints `Cannot login` only for roles that *cannot* log in, so a blank line
means the role has `LOGIN`. A `*_public` role should never show `Cannot login`; if one
does, it was created without `LOGIN` — drop it and re-create it.

### Apply the migrations

Two directories, in this order: `versions` (the versioned files) and `code` (the
repeatable ones). Every versioned migration is applied before any repeatable one — both
runners below do this, and the schema depends on it.

Migrate **as the owner**, never as a service role, so objects are owned by the deployment
role, the `pgcrypto` extension can be installed, and the grants to the service roles
succeed.

With **Evolve**:

```sh
evolve migrate postgresql \
  -c "Server=$POSTGRES_HOST;Database=$POSTGRES_DB;User Id=$POSTGRES_USER;Password=$POSTGRES_PASSWORD" \
  -l versions -l code
```

With **Flyway**:

```sh
docker run --rm -v "$PWD:/flyway/sql:ro" flyway/flyway:11-alpine \
  -url="jdbc:postgresql://$POSTGRES_HOST:5432/$POSTGRES_DB" \
  -user="$POSTGRES_USER" -password="$POSTGRES_PASSWORD" \
  -locations=filesystem:/flyway/sql/versions,filesystem:/flyway/sql/code \
  migrate
```

Running either twice is a no-op. The two runners keep their **own** history table, so a
database migrated by one is not continued by the other — pick one per database and stay
with it.

## Data-layer model

Every schema follows one model: a **schema per domain**, `SECURITY DEFINER` procedures as
the only entry point, a uniform JSONB `(pi_data, INOUT po_data)` envelope, `EXECUTE`-only
service roles with no table access, a pinned `search_path`, and ULID primary keys.
Services only `CALL` the procedures, which run as the owner. The tables and columns are the
source of truth for the data model; the service code only knows procedure names.

## Security model

Every property below is enforced by something in this tree — a role definition, a trigger,
a test — rather than promised in prose:

- **Services cannot read or write data directly.** A service role holds `EXECUTE` on the
  procedures it needs and nothing else — no table privileges anywhere, its own schema
  included. A leaked service credential therefore exposes one narrow procedure API, not the
  database. `testing/roleleak.sql` fails if a `*_public` role can reach anything beyond the
  procedures it was granted.

- **No powerful credential at runtime, and none in the files.** The owner — the only role
  that can change schemas — runs migrations and is never a service identity. The migrations
  themselves carry no credentials at all: every role and password comes from the deployment
  environment.

- **The audit trail is hardened against its own operators.** `audit.entry` and
  `audit.deletion_request` carry guard triggers that reject `UPDATE` and `DELETE`
  regardless of anyone's grants, so the trail is append-only in the database rather than by
  convention.

- **Name resolution is pinned, not inherited.** Every procedure sets its own
  `search_path` — `util` first, `public` as a co-deployment fallback, `pg_temp` last — and
  `pgcrypto` is installed into `util`, so a procedure body resolves the names it means
  rather than whatever the caller happened to have set.

## Schemas

Apply order is `util` → `registry` → `session` → `audit`.

| Schema | Holds / does |
|---|---|
| `util` | Shared primitives: `generate_ulid()`, the `result_success` / `result_error` JSON envelope, `pgcrypto`. Everything depends on it. |
| `registry` | Client-owned data: the relying-party client, its intended uses, request templates, API keys, registration certificates and the onboarding evidence. |
| `session` | The wallet-facing verification schema: the verification session and the verification report, plus the projection columns the management API reads. |
| `audit` | Append-only audit trail and the deletion-request log. |

`audit` applies last by the "most dependent schema goes last" convention, while the
dependency runs the other way: it is `registry`'s procedures that write into `audit.entry`.
That is safe because every versioned migration is applied before any repeatable one, and
because PL/pgSQL procedure bodies are late-bound — a body is resolved the first time it is
`CALL`ed, not when it is created. For the same reason the files under `code/` have no
ordering constraints among themselves.

## Roles

| Role | Login | Purpose |
|---|---|---|
| *(owner)* | yes | Owns every schema and object; migrations run as it; `SECURITY DEFINER` procedures execute as it. Never a service runtime identity. Its name comes from the connection environment. |
| `verifier_core_public` | yes | The wallet-facing verifier — `EXECUTE` on the `session` procedures. |
| `management_public` | yes | The session-authoring API — `EXECUTE` on the `session` and `registry` procedures it needs. |
| `registration_api_public` | yes | The relying-party onboarding API — `EXECUTE` on the `registry` procedures, and the audit entries they write. |

## Verifying locally

Docker is the only requirement. The database image must ship `plpgsql_check`, which the
stock PostgreSQL image does not — two lines on top of it are enough:

```sh
docker build -t pg-check - <<'EOF'
FROM postgres:17
RUN apt-get update \
  && apt-get install -y --no-install-recommends postgresql-17-plpgsql-check \
  && rm -rf /var/lib/apt/lists/*
EOF
```

Then, against a database with the roles created and the migrations applied:

```sh
export PGPASSWORD=$POSTGRES_PASSWORD
for t in testing/tests/unit.*.sql testing/roleleak.sql; do
  psql -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$t"
done

psql -X -x -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -f testing/lint-pgSQL.sql > /tmp/output.txt
sh testing/check-linter-error-steps.sh
```

- `testing/tests/unit.*.sql` — per-schema SQL unit tests.
- `testing/roleleak.sql` — asserts no `*_public` role can reach anything beyond the
  procedures it is granted.
- `testing/lint-pgSQL.sql` — `plpgsql_check` over every procedure;
  `check-linter-error-steps.sh` fails on any finding at level `error`.

CI runs exactly this on every push and pull request.

## Conventions

Versioned (`V`) migrations are **immutable once applied**: the runner checksums them, and
an edit silently diverges environments — the file in the repository stops matching what the
database recorded. A schema change ships as a **new** versioned file. Repeatable `R__`
procedure files are meant to be edited: they are re-applied whenever their checksum
changes, which is why every procedure is `CREATE OR REPLACE`.

## Project files

- [SECURITY.md](SECURITY.md) — the private route for anything exploitable, never a public issue

## Licence

EUPL-1.2 — see [LICENSE](LICENSE).
