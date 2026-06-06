#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"
skip_if_missing AUTHKIT_SMOKE_MFA_EMAIL
skip_if_missing AUTHKIT_SMOKE_MFA_PASSWORD
skip_if_missing AUTHKIT_SMOKE_MFA_CODE

login_status="$(http_json_status POST /api/v1/auth/login "$(printf '{"email":"%s","password":"%s"}' "${AUTHKIT_SMOKE_MFA_EMAIL}" "${AUTHKIT_SMOKE_MFA_PASSWORD}")" "" /tmp/authkit-mfa-login.json)"
assert_status_in "${login_status}" "MFA protected login challenge" 200 401 403

mfa_token="$(json_value /tmp/authkit-mfa-login.json '.data.mfaToken // empty')"
if [[ -z "${mfa_token}" ]]; then
  echo "SKIP: login response did not expose an mfaToken for this configured account."
  exit 0
fi

verify_body="$(printf '{"mfaToken":"%s","code":"%s"}' "${mfa_token}" "${AUTHKIT_SMOKE_MFA_CODE}")"
verify_status="$(http_json_status POST /api/v1/auth/mfa/verify-login "${verify_body}" "" /tmp/authkit-mfa-verify.json)"
assert_status "200" "${verify_status}" "MFA login verification"
