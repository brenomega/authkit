#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
backup_dir="${AUTHKIT_BACKUP_DIR:-}"
snapshot="${AUTHKIT_RESTORE_POSTGRES_SNAPSHOT:-}"
secrets_directory="${AUTHKIT_SECRETS_DIRECTORY:-}"
expected_flyway_version="${AUTHKIT_EXPECTED_FLYWAY_VERSION:-25}"

if [[ -z "${backup_dir}" || "${backup_dir}" == "/" ]]; then
  echo "FAIL: AUTHKIT_BACKUP_DIR must be a non-empty directory path." >&2
  exit 1
fi
if [[ -z "${snapshot}" ]]; then
  snapshot="$(find "${backup_dir}" -maxdepth 1 -name 'authkit-postgres-*.dump' -type f | sort | tail -n 1)"
fi
if [[ -z "${snapshot}" || ! -r "${snapshot}" ]]; then
  echo "FAIL: no readable PostgreSQL snapshot found." >&2
  exit 1
fi
if [[ -z "${secrets_directory}" || ! -d "${secrets_directory}" ]]; then
  echo "FAIL: AUTHKIT_SECRETS_DIRECTORY must contain the golden PostgreSQL secrets." >&2
  exit 1
fi
for secret_name in postgres_owner_password postgres_app_password postgres_retention_password; do
  if [[ ! -r "${secrets_directory}/${secret_name}" ]]; then
    echo "FAIL: missing readable ${secret_name}." >&2
    exit 1
  fi
done

snapshot="$(realpath "${snapshot}")"
secrets_directory="$(realpath "${secrets_directory}")"
if [[ -f "${snapshot}.sha256" ]]; then
  (
    cd "$(dirname "${snapshot}")"
    sha256sum -c "$(basename "${snapshot}.sha256")"
  )
fi

container_name="authkit-postgres-restore-check-$RANDOM-$RANDOM"
cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --name "${container_name}" \
  -e POSTGRES_USER=authkit_owner \
  -e POSTGRES_DB=authkit \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres_owner_password \
  --mount type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=536870912 \
  --mount "type=bind,source=${secrets_directory}/postgres_owner_password,target=/run/secrets/postgres_owner_password,readonly" \
  --mount "type=bind,source=${secrets_directory}/postgres_app_password,target=/run/secrets/postgres_app_password,readonly" \
  --mount "type=bind,source=${secrets_directory}/postgres_retention_password,target=/run/secrets/postgres_retention_password,readonly" \
  --mount "type=bind,source=${repo_root}/deploy/golden/init-database-roles.sh,target=/docker-entrypoint-initdb.d/10-authkit-roles.sh,readonly" \
  postgres:17-alpine >/dev/null

ready=false
for _ in $(seq 1 45); do
  ready_count="$(docker logs "${container_name}" 2>&1 | grep -c 'database system is ready to accept connections' || true)"
  if [[ "${ready_count}" -ge 2 ]] && docker exec "${container_name}" \
      pg_isready -U authkit_owner -d authkit >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "${ready}" != true ]]; then
  docker logs "${container_name}" >&2 || true
  echo "FAIL: clean PostgreSQL restore target did not become ready." >&2
  exit 1
fi

docker exec -i "${container_name}" \
  pg_restore --exit-on-error -U authkit_owner -d authkit <"${snapshot}"

restored_version="$(docker exec "${container_name}" psql -U authkit_owner -d authkit -Atqc \
  'select max(version::integer) from flyway_schema_history where success')"
if [[ "${restored_version}" != "${expected_flyway_version}" ]]; then
  echo "FAIL: restored Flyway version ${restored_version}, expected ${expected_flyway_version}." >&2
  exit 1
fi

docker exec "${container_name}" psql -U authkit_owner -d authkit -Atqc \
  "select 'users=' || count(*) from users;
   select 'bootstrap_guard=' || count(*) from authkit_bootstrap_state where completed_at is not null;
   select 'accepted_email=' || count(*) from email_outbox where status='ACCEPTED';"
echo "PostgreSQL clean-container restore check passed at Flyway version ${restored_version}."
