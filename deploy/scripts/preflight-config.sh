#!/usr/bin/env bash
set -euo pipefail

declare -A ENV_FILE_VALUES=()
failures=0

env_file="${1:-}"
if [[ -n "${env_file}" ]]; then
  if [[ ! -r "${env_file}" ]]; then
    echo "FAIL env_file: ${env_file} is not readable"
    exit 1
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    ENV_FILE_VALUES["${key}"]="${value}"
  done < "${env_file}"
fi

value() {
  local key="$1"
  local default="${2:-}"
  if [[ -n "${!key:-}" ]]; then
    printf '%s' "${!key}"
  elif [[ -v "ENV_FILE_VALUES[${key}]" ]]; then
    printf '%s' "${ENV_FILE_VALUES[${key}]}"
  else
    printf '%s' "${default}"
  fi
}

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

required() {
  local key="$1"
  local val
  val="$(value "${key}")"
  if [[ -z "${val}" || "${val}" == CHANGE-ME* || "${val}" == *CHANGE-ME* ]]; then
    fail "${key}: required and must not be CHANGE-ME"
  else
    pass "${key}: present"
  fi
}

equals() {
  local key="$1"
  local expected="$2"
  local val
  val="$(value "${key}")"
  if [[ "${val}" == "${expected}" ]]; then
    pass "${key}: ${expected}"
  else
    fail "${key}: expected ${expected}, got ${val:-<empty>}"
  fi
}

not_wildcard() {
  local key="$1"
  local val
  val="$(value "${key}")"
  if [[ -z "${val}" || "${val}" == "*" || "${val}" == *",*"* ]]; then
    fail "${key}: wildcard or empty origins are not allowed"
  else
    pass "${key}: constrained"
  fi
}

golden_file() {
  local directory="$1"
  local name="$2"
  local minimum_bytes="${3:-1}"
  local path="${directory}/${name}"
  if [[ ! -f "${path}" || ! -r "${path}" ]]; then
    fail "golden secret ${name}: missing or unreadable"
    return
  fi
  local mode size
  mode="$(stat -c '%a' "${path}")"
  size="$(wc -c < "${path}")"
  if [[ "${mode}" != "444" ]]; then
    fail "golden secret ${name}: local Compose requires mode 0444 (got ${mode})"
  elif (( size < minimum_bytes )); then
    fail "golden secret ${name}: shorter than ${minimum_bytes} bytes"
  elif grep -Eqi 'change[-_ ]?me|example|placeholder' "${path}"; then
    fail "golden secret ${name}: placeholder-like content"
  else
    pass "golden secret ${name}: readable, non-placeholder, mode 0444"
  fi
}

golden_preflight() {
  required AUTHKIT_PUBLIC_HOST
  required AUTHKIT_JWT_AUDIENCE
  required AUTHKIT_JWT_KEY_ID
  required AUTHKIT_FRONTEND_ACTIVATION_URL
  required AUTHKIT_FRONTEND_PASSWORD_RESET_URL
  required AUTHKIT_FRONTEND_EMAIL_CHANGE_URL
  required AUTHKIT_REGISTRATION_MODE
  required AUTHKIT_TERMS_VERSION
  required AUTHKIT_PRIVACY_POLICY_VERSION
  required AUTHKIT_EMAIL_FROM
  required AUTHKIT_EMAIL_PROVIDER_TYPE
  required AUTHKIT_CORS_ALLOWED_ORIGINS
  required AUTHKIT_PASSKEY_RP_ID
  required AUTHKIT_PASSKEY_ORIGINS
  required AUTHKIT_OAUTH_AUTHORIZATION_UI_URL
  required AUTHKIT_WORKER_TRUSTED_ORIGINS
  required AUTHKIT_EMAIL_TEMPLATES_DIRECTORY
  required AUTHKIT_SECRETS_DIRECTORY

  case "$(value AUTHKIT_REGISTRATION_MODE)" in
    public|restricted) pass "AUTHKIT_REGISTRATION_MODE: explicit supported value" ;;
    *) fail "AUTHKIT_REGISTRATION_MODE: must be public or restricted" ;;
  esac

  local https_key
  for https_key in AUTHKIT_FRONTEND_ACTIVATION_URL AUTHKIT_FRONTEND_PASSWORD_RESET_URL \
      AUTHKIT_FRONTEND_EMAIL_CHANGE_URL AUTHKIT_OAUTH_AUTHORIZATION_UI_URL; do
    if [[ "$(value "${https_key}")" =~ ^https://[^/[:space:]]+(/.*)?$ ]]; then
      pass "${https_key}: HTTPS"
    else
      fail "${https_key}: must be an absolute HTTPS URL"
    fi
  done

  not_wildcard AUTHKIT_CORS_ALLOWED_ORIGINS
  IFS=',' read -ra cors_origins <<< "$(value AUTHKIT_CORS_ALLOWED_ORIGINS)"
  local origin
  for origin in "${cors_origins[@]}"; do
    if [[ ! "${origin}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]]; then
      fail "AUTHKIT_CORS_ALLOWED_ORIGINS: every entry must be an exact HTTPS origin"
    fi
  done

  # The published golden topology reserves .10 for Caddy and .20 for the
  # separately authenticated worker/load runner. A broader range would let the
  # public proxy satisfy the independent network factor.
  equals AUTHKIT_WORKER_TRUSTED_ORIGINS 172.30.0.20/32

  case "$(value AUTHKIT_EMAIL_PROVIDER_TYPE)" in
    smtp)
      required AUTHKIT_SMTP_HOST
      if [[ "$(value AUTHKIT_SMTP_AUTH true)" == "true" ]]; then
        required AUTHKIT_SMTP_USERNAME
      fi
      equals AUTHKIT_SMTP_DEDUPLICATION_GUARANTEED true
      ;;
    resend) ;;
    *) fail "AUTHKIT_EMAIL_PROVIDER_TYPE: must be smtp or resend" ;;
  esac

  local env_base secrets_dir templates_dir
  env_base="$(cd "$(dirname "${env_file}")" && pwd)"
  secrets_dir="$(value AUTHKIT_SECRETS_DIRECTORY)"
  [[ "${secrets_dir}" = /* ]] || secrets_dir="${env_base}/${secrets_dir#./}"
  templates_dir="$(value AUTHKIT_EMAIL_TEMPLATES_DIRECTORY)"
  if [[ "${templates_dir}" != /* ]]; then
    fail "AUTHKIT_EMAIL_TEMPLATES_DIRECTORY: must be absolute"
  fi
  if [[ ! -d "${secrets_dir}" ]]; then
    fail "golden secret directory: missing (${secrets_dir})"
  else
    local directory_mode
    directory_mode="$(stat -c '%a' "${secrets_dir}")"
    if [[ "${directory_mode}" == "700" ]]; then
      pass "golden secret directory: mode 0700"
    else
      fail "golden secret directory: expected mode 0700, got ${directory_mode}"
    fi
    golden_file "${secrets_dir}" postgres_owner_password 32
    golden_file "${secrets_dir}" postgres_app_password 32
    golden_file "${secrets_dir}" postgres_retention_password 32
    golden_file "${secrets_dir}" redis_password 32
    golden_file "${secrets_dir}" audit_hash_pepper 32
    golden_file "${secrets_dir}" mfa_encryption_key 32
    golden_file "${secrets_dir}" worker_token 32
    golden_file "${secrets_dir}" email_provider_credential 16
    golden_file "${secrets_dir}" jwt_public.pem 128
    golden_file "${secrets_dir}" jwt_private.pem 512
    golden_file "${secrets_dir}" tls_certificate.pem 128
    golden_file "${secrets_dir}" tls_private_key.pem 128

    if openssl pkey -in "${secrets_dir}/jwt_private.pem" -check -noout >/dev/null 2>&1 \
        && openssl pkey -pubin -in "${secrets_dir}/jwt_public.pem" -noout >/dev/null 2>&1; then
      local jwt_private_pub jwt_public_pub
      jwt_private_pub="$(openssl pkey -in "${secrets_dir}/jwt_private.pem" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
      jwt_public_pub="$(openssl pkey -pubin -in "${secrets_dir}/jwt_public.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
      if [[ "${jwt_private_pub}" == "${jwt_public_pub}" ]]; then
        pass "JWT key pair: parseable and matching"
      else
        fail "JWT key pair: public/private mismatch"
      fi
    else
      fail "JWT key pair: invalid key material"
    fi

    if openssl x509 -in "${secrets_dir}/tls_certificate.pem" -noout -checkend 0 >/dev/null 2>&1 \
        && openssl x509 -in "${secrets_dir}/tls_certificate.pem" -noout \
          -checkhost "$(value AUTHKIT_PUBLIC_HOST)" >/dev/null 2>&1 \
        && openssl pkey -in "${secrets_dir}/tls_private_key.pem" -check -noout >/dev/null 2>&1; then
      local tls_cert_pub tls_private_pub
      tls_cert_pub="$(openssl x509 -in "${secrets_dir}/tls_certificate.pem" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
      tls_private_pub="$(openssl pkey -in "${secrets_dir}/tls_private_key.pem" -pubout -outform DER 2>/dev/null \
        | sha256sum | cut -d' ' -f1)"
      if [[ "${tls_cert_pub}" == "${tls_private_pub}" ]]; then
        pass "TLS certificate: hostname and private key match"
      else
        fail "TLS certificate: private-key mismatch"
      fi
    else
      fail "TLS certificate: invalid, expired, or missing AUTHKIT_PUBLIC_HOST SAN"
    fi
  fi

  local stem template_file
  for stem in email-confirmation password-recovery password-changed email-change-confirmation \
      email-change-requested email-changed email-change-cancelled; do
    for template_file in "${stem}.subject.txt" "${stem}.body.html"; do
      if [[ -s "${templates_dir}/${template_file}" && ! -L "${templates_dir}/${template_file}" ]]; then
        pass "email template ${template_file}: present"
      else
        fail "email template ${template_file}: missing, empty, or symlink"
      fi
    done
  done
}

if [[ -n "$(value AUTHKIT_PUBLIC_HOST)" ]]; then
  golden_preflight
  if [[ "${failures}" -gt 0 ]]; then
    echo "Preflight failed with ${failures} issue(s)."
    exit 1
  fi
  echo "Preflight passed."
  exit 0
fi

required DB_URL
required DB_USERNAME
required DB_PASSWORD
required JWT_PUBLIC_KEY
required JWT_PRIVATE_KEY
required AUTH_JWT_ISSUER
required AUTH_JWT_AUDIENCE
required AUTH_FRONTEND_ACTIVATION_URL
required AUTH_FRONTEND_PASSWORD_RESET_URL
required AUTH_AUDIT_HASH_PEPPER
required AUTH_MFA_SECRET_ENCRYPTION_KEY
required WORKER_TOKEN
required AUTH_REGISTRATION_MODE

case "$(value AUTH_REGISTRATION_MODE)" in
  public|restricted) pass "AUTH_REGISTRATION_MODE: explicit supported value" ;;
  *) fail "AUTH_REGISTRATION_MODE: must be public or restricted" ;;
esac

backend="$(value AUTH_TOKEN_STORAGE_BACKEND redis)"
case "${backend}" in
  redis)
    required REDIS_HOST
    required REDIS_PASSWORD
    equals AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE false
    ;;
  jdbc)
    equals AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE true
    if [[ "$(value AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK false)" == "true" ]]; then
      fail "AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK: cannot be true without Redis-backed abuse storage"
    else
      pass "AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK: compatible with JDBC token backend"
    fi
    ;;
  *)
    fail "AUTH_TOKEN_STORAGE_BACKEND: unsupported value ${backend}"
    ;;
esac

email_provider="$(value AUTH_EMAIL_PROVIDER_TYPE resend)"
case "${email_provider}" in
  logging)
    fail "AUTH_EMAIL_PROVIDER_TYPE: logging provider is not allowed for production preflight"
    ;;
  resend)
    required RESEND_API_KEY
    ;;
  smtp)
    required AUTH_EMAIL_SMTP_HOST
    if [[ "$(value AUTH_EMAIL_SMTP_AUTH true)" == "true" ]]; then
      required AUTH_EMAIL_SMTP_USERNAME
      required AUTH_EMAIL_SMTP_PASSWORD
    else
      pass "AUTH_EMAIL_SMTP_AUTH: disabled"
    fi
    if [[ "$(value AUTHKIT_PREFLIGHT_MODE production)" != "local" ]]; then
      if [[ "$(value AUTH_EMAIL_SMTP_STARTTLS_REQUIRED true)" == "true" || "$(value AUTH_EMAIL_SMTP_SSL_ENABLED false)" == "true" ]]; then
        pass "SMTP transport: TLS required or SSL enabled"
      else
        fail "SMTP transport: STARTTLS must be required or SSL enabled outside local preflight"
      fi
    else
      pass "SMTP transport: local preflight permits Mailpit-style plaintext"
    fi
    ;;
  *)
    fail "AUTH_EMAIL_PROVIDER_TYPE: unsupported value ${email_provider}"
    ;;
esac

not_wildcard AUTH_CORS_ALLOWED_ORIGINS
IFS=',' read -ra cors_origins <<< "$(value AUTH_CORS_ALLOWED_ORIGINS)"
for origin in "${cors_origins[@]}"; do
  if [[ ! "${origin}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]]; then
    fail "AUTH_CORS_ALLOWED_ORIGINS: every entry must be an exact HTTPS origin"
  fi
done
equals AUTH_CSRF_ENABLED true
equals AUTH_REFRESH_COOKIE_SECURE true
equals AUTH_REFRESH_COOKIE_SAME_SITE Strict

if [[ "$(value AUTH_EMAIL_OUTBOX_ENABLED true)" == "true" || "$(value AUTH_RETENTION_JOB_ENABLED true)" == "true" ]]; then
  equals AUTH_SCHEDULER_DISTRIBUTED_LOCK_ENABLED true
else
  pass "scheduler distributed locking: scheduled jobs disabled"
fi

argon_memory="$(value SECURITY_ARGON2_MEMORY 32768)"
argon_iterations="$(value SECURITY_ARGON2_ITERATIONS 2)"
argon_parallelism="$(value SECURITY_ARGON2_PARALLELISM 2)"
if (( argon_memory < 19456 )); then
  fail "SECURITY_ARGON2_MEMORY: below production floor"
else
  pass "SECURITY_ARGON2_MEMORY: production floor met"
fi
if (( argon_iterations < 2 )); then
  fail "SECURITY_ARGON2_ITERATIONS: below production floor"
else
  pass "SECURITY_ARGON2_ITERATIONS: production floor met"
fi
if (( argon_parallelism < 1 )); then
  fail "SECURITY_ARGON2_PARALLELISM: invalid"
else
  pass "SECURITY_ARGON2_PARALLELISM: valid"
fi

if [[ "${failures}" -gt 0 ]]; then
  echo "Preflight failed with ${failures} issue(s)."
  exit 1
fi

echo "Preflight passed."
