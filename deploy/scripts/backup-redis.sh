#!/usr/bin/env bash
set -euo pipefail

if [[ "${AUTH_TOKEN_STORAGE_BACKEND:-redis}" != "redis" ]]; then
  echo "Redis backup skipped because AUTH_TOKEN_STORAGE_BACKEND is not redis."
  exit 0
fi

backup_dir="${AUTHKIT_BACKUP_DIR:-}"
if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
redis_host="${REDIS_HOST:-}"
redis_port="${REDIS_PORT:-6379}"
redis_password="${REDIS_PASSWORD:-}"
if [[ -z "${redis_host}" || -z "${redis_password}" ]]; then
  echo "FAIL: REDIS_HOST and non-empty REDIS_PASSWORD are required for Redis backup." >&2
  exit 1
fi
mkdir -p "${backup_dir}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
outfile="${backup_dir}/authkit-redis-${timestamp}.rdb"

echo "Creating Redis RDB backup ${outfile}"
REDISCLI_AUTH="${redis_password}" redis-cli --no-auth-warning --host "${redis_host}" --port "${redis_port}" --rdb "${outfile}"
sha256sum "${outfile}" > "${outfile}.sha256"
chmod 0600 "${outfile}" "${outfile}.sha256"
echo "Redis backup complete."
