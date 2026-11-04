# Database

PostgreSQL stores user identity references, inspection cases, assessment revisions, Walrus write state, evaluation runs, and audit events. Walrus remains the durable cross-session memory store; this database records application ownership and operation state.

The first migration is transactional SQL. Apply migrations in ascending filename order and record each applied filename in the deployment's migration process. The API must scope every case and memory-reference query to the authenticated user ID.

`app_users` stores an external identity issuer and subject, not credentials. The authentication provider remains a deployment choice. Case evidence is stored as JSONB so refreshes and retries can recover the same provenance bundle; define retention and deletion behavior before production deployment.

## Local PostgreSQL

Copy `.env.example` to `.env`, then start the local PostgreSQL 17 container:

```sh
cp .env.example .env
docker compose up -d postgres
```

The service binds only to localhost and stores data in the `sieve-postgres` Docker volume. The API applies pending migrations at startup. To run the API from a shell that has sourced the local settings, use:

```sh
set -a
. ./.env
set +a
pnpm --filter @sieve/api dev
```

The example password is for local development only. Do not reuse it outside a local disposable database. To remove the container while keeping its data, run `docker compose down`; `docker compose down -v` also deletes the local database volume.

## Backup and restore rehearsal

Install the PostgreSQL client tools matching the server major version. Create a compressed, owner-only backup with `DATABASE_URL` set in the shell:

```sh
bash scripts/backup-database.sh ./sieve-backup.dump
pg_restore --list ./sieve-backup.dump
```

Restore only into a newly created, empty database. The script checks that the typed confirmation matches the target database name and refuses targets that already contain user relations. It never drops or cleans existing objects:

```sh
TARGET_DATABASE_URL='postgresql://…/sieve_restore' \
RESTORE_CONFIRM_DATABASE='sieve_restore' \
bash scripts/restore-database.sh ./sieve-backup.dump
```

After restore, start the candidate API against that database and confirm readiness and representative case, memory-status, and evaluation records before cutover. Keep backups encrypted and access-controlled in remote storage, define retention, and rehearse restores on the deployment's PostgreSQL version. The scripts do not upload, encrypt, or delete backups.

Migrations are forward-only; there are no down migrations. Roll back an application release only when its code remains compatible with the applied schema. Otherwise restore to a separate database and cut over after validation, or apply a corrective forward migration. Never roll back by dropping production tables.
