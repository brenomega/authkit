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
redis_container="${AUTHKIT_REDIS_CONTAINER:-}"
install -d -m 0700 "${backup_dir}"
backup_dir="$(realpath "${backup_dir}")"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
outfile="${backup_dir}/authkit-redis-${timestamp}.rdb"

echo "Creating Redis RDB backup ${outfile}"
if [[ -n "${redis_container}" ]]; then
  remote_snapshot="/tmp/authkit-redis-${timestamp}.rdb"
  cleanup_remote() {
    docker exec "${redis_container}" rm -f "${remote_snapshot}" >/dev/null 2>&1 || true
  }
  trap cleanup_remote EXIT
  docker exec "${redis_container}" sh -eu -c \
    'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli --no-auth-warning --rdb "$1"' \
    sh "${remote_snapshot}"
  # `docker cp` cannot read files held on the golden container's `/tmp` tmpfs
  # with some Docker storage drivers. Stream the verified file over exec instead.
  docker exec "${redis_container}" test -s "${remote_snapshot}"
  docker exec "${redis_container}" cat "${remote_snapshot}" >"${outfile}"
else
  if [[ -z "${redis_host}" || -z "${redis_password}" ]]; then
    echo "FAIL: set AUTHKIT_REDIS_CONTAINER, or REDIS_HOST plus non-empty REDIS_PASSWORD." >&2
    exit 1
  fi
  command -v redis-cli >/dev/null 2>&1 || { echo "FAIL: redis-cli is required for remote mode." >&2; exit 1; }
  REDISCLI_AUTH="${redis_password}" redis-cli --no-auth-warning \
    --host "${redis_host}" --port "${redis_port}" --rdb "${outfile}"
fi
(
  cd "${backup_dir}"
  sha256sum "$(basename "${outfile}")" >"$(basename "${outfile}").sha256"
)
chmod 0600 "${outfile}" "${outfile}.sha256"
echo "Redis backup complete."
