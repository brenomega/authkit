#!/usr/bin/env bash
set -euo pipefail

backup_dir="${AUTHKIT_BACKUP_DIR:-}"
if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
mkdir -p "${backup_dir}"

db_url="${DB_URL:-}"
db_user="${DB_USERNAME:-${PGUSER:-}}"
db_password="${DB_PASSWORD:-${PGPASSWORD:-}}"
if [[ -z "${db_url}" || -z "${db_user}" || -z "${db_password}" ]]; then
  echo "FAIL: DB_URL, DB_USERNAME, and DB_PASSWORD are required." >&2
  exit 1
fi

if [[ "${db_url}" != jdbc:postgresql://* ]]; then
  echo "FAIL: DB_URL must be a PostgreSQL JDBC URL." >&2
  exit 1
fi

url="${db_url#jdbc:postgresql://}"
hostport="${url%%/*}"
database="${url#*/}"
database="${database%%\?*}"
host="${hostport%%:*}"
port="${hostport#*:}"
if [[ "${port}" == "${hostport}" ]]; then
  port="5432"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
outfile="${backup_dir}/authkit-postgres-${timestamp}.dump"

echo "Creating PostgreSQL backup ${outfile}"
PGPASSWORD="${db_password}" pg_dump \
  --host "${host}" \
  --port "${port}" \
  --username "${db_user}" \
  --dbname "${database}" \
  --format custom \
  --no-owner \
  --no-privileges \
  --file "${outfile}"

sha256sum "${outfile}" > "${outfile}.sha256"
chmod 0600 "${outfile}" "${outfile}.sha256"
echo "Backup complete. Verify restore with deploy/scripts/restore-postgres-check.sh before trusting this backup set."
