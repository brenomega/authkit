#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proof_root="$(mktemp -d)"
cleanup() {
  rm -rf "${proof_root}"
}
trap cleanup EXIT

secrets_dir="${proof_root}/secrets"
templates_dir="${proof_root}/templates"
env_file="${proof_root}/golden.env"
mkdir -m 0700 "${secrets_dir}"
mkdir -p "${templates_dir}"
cp "${repo_root}"/src/test/resources/email-templates/* "${templates_dir}/"

for secret_name in postgres_owner_password postgres_app_password postgres_retention_password \
    redis_password audit_hash_pepper mfa_encryption_key worker_token email_provider_credential; do
  openssl rand -base64 48 >"${secrets_dir}/${secret_name}"
done
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${secrets_dir}/jwt_private.pem" >/dev/null 2>&1
openssl pkey -in "${secrets_dir}/jwt_private.pem" -pubout -out "${secrets_dir}/jwt_public.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=authkit.local.test" -addext "subjectAltName=DNS:authkit.local.test" \
  -keyout "${secrets_dir}/tls_private_key.pem" -out "${secrets_dir}/tls_certificate.pem" >/dev/null 2>&1
chmod 0444 "${secrets_dir}"/*

cp "${repo_root}/deploy/golden/.env.example" "${env_file}"
sed -i \
  -e 's/^AUTHKIT_PUBLIC_HOST=.*/AUTHKIT_PUBLIC_HOST=authkit.local.test/' \
  -e 's/^AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=.*/AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=true/' \
  -e "s#^AUTHKIT_EMAIL_TEMPLATES_DIRECTORY=.*#AUTHKIT_EMAIL_TEMPLATES_DIRECTORY=${templates_dir}#" \
  -e "s#^AUTHKIT_SECRETS_DIRECTORY=.*#AUTHKIT_SECRETS_DIRECTORY=${secrets_dir}#" \
  "${env_file}"

"${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}"
docker compose --env-file "${env_file}" -f "${repo_root}/deploy/golden/compose.yml" config --quiet

expect_failure() {
  local label="$1"
  shift
  if "$@" >"${proof_root}/${label}.stdout" 2>"${proof_root}/${label}.stderr"; then
    echo "FAIL ${label}: command unexpectedly succeeded" >&2
    return 1
  fi
  echo "PASS ${label}: rejected as required"
}

sed -i 's/^AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=.*/AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=false/' "${env_file}"
expect_failure smtp-without-deduplication "${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}"
sed -i 's/^AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=.*/AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED=true/' "${env_file}"

sed -i 's/^AUTHKIT_PUBLIC_HOST=.*/AUTHKIT_PUBLIC_HOST=wrong.local.test/' "${env_file}"
expect_failure tls-hostname-mismatch "${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}"
sed -i 's/^AUTHKIT_PUBLIC_HOST=.*/AUTHKIT_PUBLIC_HOST=authkit.local.test/' "${env_file}"

sed -i 's/^AUTHKIT_REGISTRATION_MODE=.*/AUTHKIT_REGISTRATION_MODE=/' "${env_file}"
expect_failure omitted-registration-preflight "${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}"
expect_failure omitted-registration-compose docker compose --env-file "${env_file}" \
  -f "${repo_root}/deploy/golden/compose.yml" config --quiet

sed -i 's/^AUTHKIT_REGISTRATION_MODE=.*/AUTHKIT_REGISTRATION_MODE=unsupported/' "${env_file}"
expect_failure invalid-registration-preflight "${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}"
expect_failure invalid-registration-compose docker compose --env-file "${env_file}" \
  -f "${repo_root}/deploy/golden/compose.yml" config --quiet

for registration_mode in public restricted; do
  sed -i "s/^AUTHKIT_REGISTRATION_MODE=.*/AUTHKIT_REGISTRATION_MODE=${registration_mode}/" "${env_file}"
  "${repo_root}/deploy/scripts/preflight-config.sh" "${env_file}" >/dev/null
  docker compose --env-file "${env_file}" -f "${repo_root}/deploy/golden/compose.yml" config --quiet
  echo "PASS registration-${registration_mode}: preflight and Compose accepted"
done

echo "Golden preflight proof passed."
