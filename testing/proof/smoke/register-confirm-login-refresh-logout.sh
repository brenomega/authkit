#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"
require_cmd jq
proof_tmp="$(mktemp -d)"
trap 'rm -rf "${proof_tmp}"' EXIT
cookie_jar="${proof_tmp}/cookies.txt"
csrf_cookie="${AUTH_CSRF_COOKIE_NAME:-XSRF-TOKEN}"
csrf_header="${AUTH_CSRF_HEADER_NAME:-X-XSRF-TOKEN}"

email="${AUTHKIT_SMOKE_EMAIL:-$(unique_email register)}"
password="${AUTHKIT_SMOKE_PASSWORD:-AuthKit-Proof-Password-32!}"
response_file="/tmp/authkit-register-response.json"

register_body="$(printf '{"email":"%s","password":"%s","termsAccepted":true,"privacyPolicyAccepted":true}' "${email}" "${password}")"
status="$(http_json_status POST /api/v1/auth/register "${register_body}" "" "${response_file}")"
assert_status_in "${status}" "register $(mask_email "${email}")" 201 202

skip_if_missing AUTHKIT_SMOKE_CONFIRMATION_TOKEN

confirm_body="$(printf '{"token":"%s"}' "${AUTHKIT_SMOKE_CONFIRMATION_TOKEN}")"
confirm_status="$(http_json_status POST /api/v1/auth/email-confirmation/confirm "${confirm_body}" "" /tmp/authkit-confirm-response.json)"
assert_status "200" "${confirm_status}" "email confirmation"

login_status="$(curl --silent --show-error --output "${proof_tmp}/login.json" --write-out '%{http_code}' \
  --cookie-jar "${cookie_jar}" --header 'Content-Type: application/json' \
  --data "$(jq -nc --arg email "${email}" --arg password "${password}" '{email:$email,password:$password}')" \
  "${AUTHKIT_BASE_URL}/api/v1/auth/login")"
assert_status "200" "${login_status}" "login"

access_token="$(json_value "${proof_tmp}/login.json" '.data.accessToken // empty')"
if [[ -z "${access_token}" ]]; then
  echo "FAIL: login did not return an access token." >&2
  exit 1
fi

csrf_value="$(awk -v name="${csrf_cookie}" '$6 == name {print $7}' "${cookie_jar}")"
[[ -n "${csrf_value}" ]] || { echo 'FAIL: login did not set the required CSRF cookie.' >&2; exit 1; }
refresh_status="$(curl --silent --show-error --output "${proof_tmp}/refresh.json" --write-out '%{http_code}' \
  --request POST --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
  --header "${csrf_header}: ${csrf_value}" "${AUTHKIT_BASE_URL}/api/v1/auth/refresh")"
assert_status 200 "${refresh_status}" refresh
refreshed_token="$(json_value "${proof_tmp}/refresh.json" '.data.accessToken // empty')"
[[ -n "${refreshed_token}" && "${refreshed_token}" != "${access_token}" ]] || {
  echo 'FAIL: refresh did not issue a new access token.' >&2; exit 1;
}
csrf_value="$(awk -v name="${csrf_cookie}" '$6 == name {print $7}' "${cookie_jar}")"
[[ -n "${csrf_value}" ]] || { echo 'FAIL: refresh did not set the required CSRF cookie.' >&2; exit 1; }
logout_status="$(curl --silent --show-error --output "${proof_tmp}/logout.json" --write-out '%{http_code}' \
  --request POST --cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
  --header "${csrf_header}: ${csrf_value}" "${AUTHKIT_BASE_URL}/api/v1/auth/logout")"
assert_status 200 "${logout_status}" logout
revoked_status="$(http_json_status GET /api/v1/users/me '' "${refreshed_token}" "${proof_tmp}/revoked.json")"
assert_status 401 "${revoked_status}" 'access after logout'
echo 'PASS: register, confirmation, login, cookie-backed refresh, logout and post-logout denial.'
