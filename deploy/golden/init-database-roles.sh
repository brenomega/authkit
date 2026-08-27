#!/bin/sh
set -eu

read_secret() {
  secret_file="$1"
  if [ ! -r "${secret_file}" ]; then
    echo "Required PostgreSQL bootstrap secret is not readable: ${secret_file}" >&2
    exit 1
  fi
  secret_value="$(sed -e '${s/[[:space:]]*$//;}' "${secret_file}")"
  if [ -z "${secret_value}" ]; then
    echo "Required PostgreSQL bootstrap secret is empty: ${secret_file}" >&2
    exit 1
  fi
  printf '%s' "${secret_value}"
}

app_password="$(read_secret /run/secrets/postgres_app_password)"
retention_password="$(read_secret /run/secrets/postgres_retention_password)"

psql --set ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
  --set db_name="${POSTGRES_DB}" --set app_password="${app_password}" \
  --set retention_password="${retention_password}" <<'EOSQL'
CREATE ROLE authkit_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE authkit_retention NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE authkit_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD :'app_password';
CREATE ROLE authkit_retention_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD :'retention_password';
GRANT authkit_runtime TO authkit_app;
GRANT authkit_retention TO authkit_retention_worker;
GRANT CONNECT ON DATABASE :"db_name" TO authkit_app, authkit_retention_worker;
EOSQL
