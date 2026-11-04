#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "Set DATABASE_URL to the PostgreSQL database to back up." >&2
  exit 2
fi

backup_path=${1:-"sieve-$(date -u +%Y%m%dT%H%M%SZ).dump"}
if [[ -e "$backup_path" ]]; then
  echo "Refusing to overwrite existing backup: $backup_path" >&2
  exit 2
fi

umask 077
temporary_path=$(mktemp "${backup_path}.tmp.XXXXXX")
trap 'rm -f -- "$temporary_path"' EXIT
if command -v pg_dump >/dev/null 2>&1; then
  pg_dump --format=custom --no-owner --no-privileges --file="$temporary_path" "$DATABASE_URL"
elif [[ "${DATABASE_DOCKER_SERVICE:-}" == "postgres" ]]; then
  case "$DATABASE_URL" in
    postgresql://*@127.0.0.1:5432/*|postgresql://*@localhost:5432/*|postgres://*@127.0.0.1:5432/*|postgres://*@localhost:5432/*) ;;
    *) echo "Docker fallback only accepts a localhost PostgreSQL URL on port 5432." >&2; exit 2 ;;
  esac
  url_database=${DATABASE_URL%%\?*}
  url_database=${url_database##*/}
  compose_database=$(docker compose exec -T postgres sh -c 'printf "%s" "$POSTGRES_DB"')
  if [[ "$url_database" != "$compose_database" ]]; then
    echo "DATABASE_URL database name does not match the Compose PostgreSQL database." >&2
    exit 2
  fi
  docker compose exec -T postgres sh -ec 'exec pg_dump --format=custom --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$temporary_path"
else
  echo "Install PostgreSQL client tools or set DATABASE_DOCKER_SERVICE=postgres for the local Compose database." >&2
  exit 2
fi
mv -- "$temporary_path" "$backup_path"
trap - EXIT
chmod 600 "$backup_path"
printf 'Database backup written to %s\n' "$backup_path"
