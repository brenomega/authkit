#!/usr/bin/env bash
set -euo pipefail

backup_dir="${AUTHKIT_BACKUP_DIR:-}"
dump_file="${AUTHKIT_RESTORE_DUMP:-}"
if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
if [[ -z "${dump_file}" ]]; then
  dump_file="$(find "${backup_dir}" -maxdepth 1 -name 'authkit-postgres-*.dump' -type f | sort | tail -n 1)"
fi
if [[ -z "${dump_file}" || ! -r "${dump_file}" ]]; then
  echo "FAIL: no readable PostgreSQL dump found." >&2
  exit 1
fi
if [[ -f "${dump_file}.sha256" ]]; then
  sha256sum -c "${dump_file}.sha256"
fi

db_url="${DB_URL:-}"
db_user="${DB_USERNAME:-${PGUSER:-}}"
db_password="${DB_PASSWORD:-${PGPASSWORD:-}}"
if [[ -z "${db_url}" || -z "${db_user}" || -z "${db_password}" ]]; then
  echo "FAIL: DB_URL, DB_USERNAME, and DB_PASSWORD are required." >&2
  exit 1
fi

url="${db_url#jdbc:postgresql://}"
hostport="${url%%/*}"
host="${hostport%%:*}"
port="${hostport#*:}"
if [[ "${port}" == "${hostport}" ]]; then
  port="5432"
fi

tmp_db="authkit_restore_check_$(date -u +%Y%m%d%H%M%S)_$RANDOM"
cleanup() {
  PGPASSWORD="${db_password}" dropdb --if-exists --host "${host}" --port "${port}" --username "${db_user}" "${tmp_db}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating temporary restore-check database ${tmp_db}"
PGPASSWORD="${db_password}" createdb --host "${host}" --port "${port}" --username "${db_user}" "${tmp_db}"
PGPASSWORD="${db_password}" pg_restore --host "${host}" --port "${port}" --username "${db_user}" --dbname "${tmp_db}" --no-owner --no-privileges "${dump_file}"
PGPASSWORD="${db_password}" psql --host "${host}" --port "${port}" --username "${db_user}" --dbname "${tmp_db}" --tuples-only --command "select count(*) from flyway_schema_history;" >/dev/null

echo "Restore check passed for ${dump_file}. Temporary database will be removed."
