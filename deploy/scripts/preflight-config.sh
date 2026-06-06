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
equals AUTH_CSRF_ENABLED true
equals AUTH_REFRESH_COOKIE_SECURE true

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
