#!/usr/bin/env bash
set -euo pipefail

backup_dir="${AUTHKIT_BACKUP_DIR:-}"
postgres_container="${AUTHKIT_POSTGRES_CONTAINER:-}"
if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
if [[ -z "${postgres_container}" ]]; then
  echo "FAIL: AUTHKIT_POSTGRES_CONTAINER is required." >&2
  exit 1
fi

install -d -m 0700 "${backup_dir}"
backup_dir="$(realpath "${backup_dir}")"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot="${backup_dir}/authkit-postgres-${timestamp}.dump"
umask 077

# Roles and passwords are recreated from the golden init script and mounted
# secrets during restore. Avoid exporting password hashes with pg_dumpall.
docker exec "${postgres_container}" \
  pg_dump -U authkit_owner -d authkit -Fc >"${snapshot}"
test -s "${snapshot}"
(
  cd "${backup_dir}"
  sha256sum "$(basename "${snapshot}")" >"$(basename "${snapshot}").sha256"
)
echo "PostgreSQL backup and checksum created in ${backup_dir}."
