# Local database restore rehearsal

**Date:** 2026-11-05
**Database version:** PostgreSQL 17 Alpine
**Result:** Passed

## Procedure

The healthy local Compose PostgreSQL service was used as the source. A custom-format backup was created with `scripts/backup-database.sh`, using its Docker fallback because host `pg_dump` and `pg_restore` were unavailable.

The backup was restored with `scripts/restore-database.sh` into a new database named `sieve_restore_rehearsal_20261105`. The restore script verified the typed database-name confirmation and rejected non-empty targets by design. The source database was not changed.

After restore, exact row counts were compared for all six application tables:

- `app_users`
- `inspection_cases`
- `assessment_revisions`
- `threat_memory_writes`
- `evaluation_runs`
- `audit_events`

Every count matched. The rehearsal target database and temporary backup file were removed after the comparison. No production service or remote database was involved.

## Limits

This checks the local backup and restore path and application-table row-count parity. It does not verify API cutover, application-level reads after restore, remote backup storage, encryption, retention, or compatibility with a managed deployment's PostgreSQL configuration. Repeat the rehearsal on the deployment's PostgreSQL version and validate representative API reads before any real cutover.
