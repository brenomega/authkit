#!/usr/bin/env bash

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "FAIL: ${name} is required." >&2
    exit 1
  fi
}

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "FAIL: ${name} is required." >&2
    exit 1
  fi
}

refuse_production() {
  local base_url="$1"
  case "${base_url}" in
    *localhost*|*127.0.0.1*|*.local*|*.test*|*.internal*|*.hml*|*.staging*) return 0 ;;
    *)
      if [[ "${ALLOW_PRODUCTION_PROOF:-false}" != "true" ]]; then
        echo "FAIL: refusing production-looking URL ${base_url}. Set ALLOW_PRODUCTION_PROOF=true only for an approved proof window." >&2
        exit 1
      fi
      ;;
  esac
}

mask_email() {
  local email="$1"
  local local_part="${email%@*}"
  local domain="${email#*@}"
  printf '%s***@%s' "${local_part:0:1}" "${domain}"
}

unique_email() {
  local prefix="${1:-authkit-proof}"
  printf '%s+%s@example.test' "${prefix}" "$(date -u +%Y%m%d%H%M%S)-$RANDOM"
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL: ${label} expected HTTP ${expected}, got ${actual}" >&2
    exit 1
  fi
  echo "PASS: ${label} returned HTTP ${actual}"
}

assert_status_in() {
  local actual="$1"
  local label="$2"
  shift 2
  local expected
  for expected in "$@"; do
    if [[ "${actual}" == "${expected}" ]]; then
      echo "PASS: ${label} returned HTTP ${actual}"
      return 0
    fi
  done
  echo "FAIL: ${label} returned HTTP ${actual}; expected one of $*" >&2
  exit 1
}

http_json_status() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-}"
  local output="${5:-/tmp/authkit-proof-response.json}"
  local args=(--silent --show-error --output "${output}" --write-out '%{http_code}' --request "${method}" --header 'Content-Type: application/json')
  if [[ -n "${token}" ]]; then
    args+=(--header "Authorization: Bearer ${token}")
  fi
  if [[ -n "${body}" ]]; then
    args+=(--data "${body}")
  fi
  curl "${args[@]}" "${AUTHKIT_BASE_URL}${path}"
}

http_form_status() {
  local method="$1"
  local path="$2"
  local form="$3"
  local output="${4:-/tmp/authkit-proof-response.json}"
  curl --silent --show-error --output "${output}" --write-out '%{http_code}' \
    --request "${method}" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data "${form}" \
    "${AUTHKIT_BASE_URL}${path}"
}

json_value() {
  local file="$1"
  local expression="$2"
  require_cmd jq
  jq -r "${expression}" "${file}"
}

skip_if_missing() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "SKIP: ${name} is not set."
    exit 0
  fi
}
