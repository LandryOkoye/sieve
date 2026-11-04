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

use_docker=false
if command -v psql >/dev/null 2>&1 && command -v pg_restore >/dev/null 2>&1; then
  target_name=$(psql "$TARGET_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT current_database()')
elif [[ "${TARGET_DATABASE_DOCKER_SERVICE:-}" == "postgres" ]]; then
  case "$TARGET_DATABASE_URL" in
    postgresql://*@127.0.0.1:5432/*|postgresql://*@localhost:5432/*|postgres://*@127.0.0.1:5432/*|postgres://*@localhost:5432/*) ;;
    *) echo "Docker fallback only accepts a localhost PostgreSQL URL on port 5432." >&2; exit 2 ;;
  esac
  target_name=${TARGET_DATABASE_URL%%\?*}
  target_name=${target_name##*/}
  if [[ ! "$target_name" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Target database name is not supported by the local Docker fallback." >&2
    exit 2
  fi
  use_docker=true
else
  echo "Install PostgreSQL client tools or set TARGET_DATABASE_DOCKER_SERVICE=postgres for the local Compose database." >&2
  exit 2
fi

psql_target() {
  if [[ "$use_docker" == true ]]; then
    docker compose exec -T postgres sh -ec 'database=$1; shift; exec psql -U "$POSTGRES_USER" -d "$database" "$@"' sh "$target_name" "$@"
  else
    psql "$TARGET_DATABASE_URL" "$@"
  fi
}

if [[ "$RESTORE_CONFIRM_DATABASE" != "$target_name" ]]; then
  echo "Confirmation did not match target database '$target_name'; refusing restore." >&2
  exit 2
fi

table_count=$(psql_target -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')")
if [[ "$table_count" != "0" ]]; then
  echo "Target database '$target_name' contains user relations; restore only into a fresh empty database." >&2
  exit 2
fi

if [[ "$use_docker" == true ]]; then
  docker compose exec -T postgres pg_restore --list < "$backup_path" >/dev/null
  docker compose exec -T postgres sh -ec 'database=$1; exec pg_restore --exit-on-error --no-owner --no-privileges -U "$POSTGRES_USER" --dbname="$database"' sh "$target_name" < "$backup_path"
else
  pg_restore --list "$backup_path" >/dev/null
  pg_restore --exit-on-error --no-owner --no-privileges --dbname="$TARGET_DATABASE_URL" "$backup_path"
fi
printf 'Restore completed into database %s. Validate it before application cutover.\n' "$target_name"
