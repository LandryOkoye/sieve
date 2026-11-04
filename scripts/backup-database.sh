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
pg_dump --format=custom --no-owner --no-privileges --file="$temporary_path" "$DATABASE_URL"
mv -- "$temporary_path" "$backup_path"
trap - EXIT
chmod 600 "$backup_path"
printf 'Database backup written to %s\n' "$backup_path"
