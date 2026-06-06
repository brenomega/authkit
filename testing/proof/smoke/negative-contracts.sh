#!/usr/bin/env bash
set -euo pipefail

AUTHKIT_BASE_URL="${AUTHKIT_BASE_URL:-}"
ALLOW_PRODUCTION_PROOF="${ALLOW_PRODUCTION_PROOF:-false}"
FIXTURE_DIR="${FIXTURE_DIR:-target/contract-fixtures}"

if [[ -z "${AUTHKIT_BASE_URL}" ]]; then
  echo "FAIL: AUTHKIT_BASE_URL is required." >&2
  exit 1
fi

case "${AUTHKIT_BASE_URL}" in
  *localhost*|*127.0.0.1*|*.local*|*.test*|*.internal*|*.hml*|*.staging*) ;;
  *)
    if [[ "${ALLOW_PRODUCTION_PROOF}" != "true" ]]; then
      echo "FAIL: refusing production-looking AUTHKIT_BASE_URL. Set ALLOW_PRODUCTION_PROOF=true only for an approved proof window." >&2
      exit 1
    fi
    ;;
esac

if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "FAIL: fixture directory ${FIXTURE_DIR} is missing. Run testing/proof/fixtures/generate-test-tokens.sh first." >&2
  exit 1
fi

require_token() {
  local name="$1"
  local path="${FIXTURE_DIR}/${name}.jwt"
  if [[ ! -s "${path}" ]]; then
    echo "FAIL: missing generated fixture ${path}" >&2
    exit 1
  fi
}

http_status() {
  local method="$1"
  local path="$2"
  local token_name="$3"
  local token
  token="$(<"${FIXTURE_DIR}/${token_name}.jwt")"
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --request "${method}" \
    --header "Authorization: Bearer ${token}" \
    "${AUTHKIT_BASE_URL}${path}"
}

run_case() {
  local name="$1"
  local method="$2"
  local path="$3"
  local token_name="$4"
  local expected="$5"
  require_token "${token_name}"

  local actual
  actual="$(http_status "${method}" "${path}" "${token_name}")"
  printf '%-44s %-6s %-35s expected=%s actual=%s\n' "${name}" "${method}" "${path}" "${expected}" "${actual}"
  [[ "${actual}" == "${expected}" ]]
}

failures=0

run_case "oauth token on first-party API" "GET" "/api/v1/users/me" "oauth-token-used-on-first-party-api" "401" || failures=$((failures + 1))
run_case "ID token on first-party API" "GET" "/api/v1/users/me" "id-token-used-on-api" "401" || failures=$((failures + 1))
run_case "wrong audience on first-party API" "GET" "/api/v1/users/me" "wrong-audience" "401" || failures=$((failures + 1))
run_case "first-party token on userinfo" "GET" "/oauth2/userinfo" "first-party-token-used-on-oauth-userinfo" "400" || failures=$((failures + 1))
run_case "ID token on userinfo" "GET" "/oauth2/userinfo" "valid-id-token" "400" || failures=$((failures + 1))

if [[ "${failures}" -gt 0 ]]; then
  echo "FAIL: ${failures} negative contract case(s) returned an unexpected status." >&2
  exit 1
fi

echo "PASS: negative contract token class checks matched expected statuses."
