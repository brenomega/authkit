#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"

if [[ -n "${AUTHKIT_OAUTH_ACCESS_TOKEN:-}" ]]; then
  status="$(curl --silent --show-error --output /tmp/authkit-userinfo.json --write-out '%{http_code}' \
    --header "Authorization: Bearer ${AUTHKIT_OAUTH_ACCESS_TOKEN}" \
    "${AUTHKIT_BASE_URL}/oauth2/userinfo")"
  assert_status "200" "${status}" "OAuth userinfo"
  exit 0
fi

if [[ -z "${AUTHKIT_OAUTH_CODE:-}" || -z "${AUTHKIT_OAUTH_CLIENT_ID:-}" || -z "${AUTHKIT_OAUTH_REDIRECT_URI:-}" || -z "${AUTHKIT_OAUTH_CODE_VERIFIER:-}" ]]; then
  echo "SKIP: set AUTHKIT_OAUTH_ACCESS_TOKEN or the OAuth code-exchange variables to exercise OAuth userinfo."
  exit 0
fi

form="grant_type=authorization_code&code=${AUTHKIT_OAUTH_CODE}&redirect_uri=${AUTHKIT_OAUTH_REDIRECT_URI}&client_id=${AUTHKIT_OAUTH_CLIENT_ID}&code_verifier=${AUTHKIT_OAUTH_CODE_VERIFIER}"
token_status="$(http_form_status POST /oauth2/token "${form}" /tmp/authkit-oauth-token.json)"
assert_status "200" "${token_status}" "OAuth token exchange"

access_token="$(json_value /tmp/authkit-oauth-token.json '.access_token // empty')"
if [[ -z "${access_token}" ]]; then
  echo "FAIL: OAuth token exchange did not return access_token." >&2
  exit 1
fi

userinfo_status="$(curl --silent --show-error --output /tmp/authkit-userinfo.json --write-out '%{http_code}' \
  --header "Authorization: Bearer ${access_token}" \
  "${AUTHKIT_BASE_URL}/oauth2/userinfo")"
assert_status "200" "${userinfo_status}" "OAuth userinfo"
