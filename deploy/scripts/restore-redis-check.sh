#!/usr/bin/env bash
set -euo pipefail

backup_dir="${AUTHKIT_BACKUP_DIR:-}"
snapshot="${AUTHKIT_RESTORE_REDIS_SNAPSHOT:-}"
if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
if [[ -z "${snapshot}" ]]; then
  snapshot="$(find "${backup_dir}" -maxdepth 1 -name 'authkit-redis-*.rdb' -type f | sort | tail -n 1)"
fi
if [[ -z "${snapshot}" || ! -r "${snapshot}" ]]; then
  echo "FAIL: no readable Redis RDB snapshot found." >&2
  exit 1
fi
snapshot="$(realpath "${snapshot}")"
if [[ -f "${snapshot}.sha256" ]]; then
  checksum_directory="$(dirname "${snapshot}")"
  checksum_file="$(basename "${snapshot}.sha256")"
  (
    cd "${checksum_directory}"
    sha256sum -c "${checksum_file}"
  )
fi
command -v docker >/dev/null 2>&1 || { echo "FAIL: docker is required." >&2; exit 1; }

restore_password="authkit-restore-check-$RANDOM-$RANDOM"
container_name="authkit-redis-restore-check-$RANDOM-$RANDOM"
volume_name="${container_name}-data"
cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  docker volume rm -f "${volume_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "${volume_name}" >/dev/null
docker run --rm --user root --entrypoint sh \
  --mount "type=volume,source=${volume_name},target=/data" \
  --mount "type=bind,source=${snapshot},target=/source/dump.rdb,readonly" \
  redis:7.4-alpine -c \
  'cp /source/dump.rdb /data/dump.rdb && chown redis:redis /data/dump.rdb && chmod 0600 /data/dump.rdb'

docker run --detach --name "${container_name}" \
  --user redis:redis --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=volume,source=${volume_name},target=/data" \
  --entrypoint redis-server redis:7.4-alpine \
  --dir /data --dbfilename dump.rdb --appendonly no --requirepass "${restore_password}" >/dev/null

for _ in $(seq 1 30); do
  if docker exec -e REDISCLI_AUTH="${restore_password}" "${container_name}" \
      redis-cli --no-auth-warning ping 2>/dev/null | grep -q PONG; then
    restored_keys="$(docker exec -e REDISCLI_AUTH="${restore_password}" "${container_name}" \
      redis-cli --no-auth-warning dbsize)"
    echo "Redis clean-container restore check passed; restored key count: ${restored_keys}."
    exit 0
  fi
  sleep 1
done

docker logs "${container_name}" >&2 || true
echo "FAIL: restored Redis did not become ready." >&2
exit 1
