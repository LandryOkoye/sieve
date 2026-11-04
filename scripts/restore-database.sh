#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "${TARGET_DATABASE_URL:-}" || -z "${RESTORE_CONFIRM_DATABASE:-}" ]]; then
  echo "Usage: TARGET_DATABASE_URL=... RESTORE_CONFIRM_DATABASE=<target-name> $0 <backup.dump>" >&2
  exit 2
fi

backup_path=$1
if [[ ! -r "$backup_path" ]]; then
  echo "Backup file is not readable: $backup_path" >&2
  exit 2
fi

target_name=$(psql "$TARGET_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT current_database()')
if [[ "$RESTORE_CONFIRM_DATABASE" != "$target_name" ]]; then
  echo "Confirmation did not match target database '$target_name'; refusing restore." >&2
  exit 2
fi

table_count=$(psql "$TARGET_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')")
if [[ "$table_count" != "0" ]]; then
  echo "Target database '$target_name' contains user relations; restore only into a fresh empty database." >&2
  exit 2
fi

pg_restore --list "$backup_path" >/dev/null
pg_restore --exit-on-error --no-owner --no-privileges --dbname="$TARGET_DATABASE_URL" "$backup_path"
printf 'Restore completed into database %s. Validate it before application cutover.\n' "$target_name"
