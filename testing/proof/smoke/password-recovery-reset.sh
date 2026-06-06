#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"

email="${AUTHKIT_SMOKE_RECOVERY_EMAIL:-${AUTHKIT_SMOKE_EMAIL:-$(unique_email recovery)}}"
request_status="$(http_json_status POST /api/v1/auth/password-recovery/request "$(printf '{"email":"%s"}' "${email}")" "" /tmp/authkit-recovery-request.json)"
assert_status "200" "${request_status}" "password recovery request"

if [[ -z "${AUTHKIT_SMOKE_RECOVERY_TOKEN:-}" ]]; then
  echo "SKIP: set AUTHKIT_SMOKE_RECOVERY_TOKEN from the local email sink to execute reset."
  exit 0
fi

new_password="${AUTHKIT_SMOKE_NEW_PASSWORD:-AuthKit-Proof-New-Password-32!}"
reset_body="$(printf '{"token":"%s","newPassword":"%s"}' "${AUTHKIT_SMOKE_RECOVERY_TOKEN}" "${new_password}")"
reset_status="$(http_json_status POST "/api/v1/auth/password-recovery/reset?email=${email}" "${reset_body}" "" /tmp/authkit-recovery-reset.json)"
assert_status "200" "${reset_status}" "password recovery reset"
