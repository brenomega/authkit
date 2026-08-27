#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"

email="${AUTHKIT_SMOKE_EMAIL:-$(unique_email register)}"
password="${AUTHKIT_SMOKE_PASSWORD:-AuthKit-Proof-Password-32!}"
response_file="/tmp/authkit-register-response.json"

register_body="$(printf '{"email":"%s","password":"%s","termsAccepted":true,"privacyPolicyAccepted":true}' "${email}" "${password}")"
status="$(http_json_status POST /api/v1/auth/register "${register_body}" "" "${response_file}")"
assert_status_in "${status}" "register $(mask_email "${email}")" 201 202

if [[ -z "${AUTHKIT_SMOKE_CONFIRMATION_TOKEN:-}" ]]; then
  echo "SKIP: set AUTHKIT_SMOKE_CONFIRMATION_TOKEN from the local email sink to continue confirm/login/refresh/logout."
  exit 0
fi

confirm_body="$(printf '{"token":"%s"}' "${AUTHKIT_SMOKE_CONFIRMATION_TOKEN}")"
confirm_status="$(http_json_status POST /api/v1/auth/email-confirmation/confirm "${confirm_body}" "" /tmp/authkit-confirm-response.json)"
assert_status "200" "${confirm_status}" "email confirmation"

login_status="$(http_json_status POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "${email}" "${password}")" "" /tmp/authkit-login-response.json)"
assert_status "200" "${login_status}" "login"

access_token="$(json_value /tmp/authkit-login-response.json '.data.accessToken // empty')"
if [[ -z "${access_token}" ]]; then
  echo "FAIL: login did not return an access token." >&2
  exit 1
fi

echo "PASS: login returned an access token. Refresh/logout require browser cookie capture and are covered by integration tests or a cookie-aware client proof."
