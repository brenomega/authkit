#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"
skip_if_missing AUTHKIT_ACCESS_TOKEN

status="$(http_json_status GET '/api/v1/users/me/sessions?limit=50' "" "${AUTHKIT_ACCESS_TOKEN}" /tmp/authkit-sessions.json)"
assert_status "200" "${status}" "session list first page"

if [[ -n "${AUTHKIT_REVOKE_JTI:-}" ]]; then
  revoke_status="$(curl --silent --show-error --output /tmp/authkit-session-revoke.json --write-out '%{http_code}' \
    --request DELETE \
    --header "Authorization: Bearer ${AUTHKIT_ACCESS_TOKEN}" \
    "${AUTHKIT_BASE_URL}/api/v1/users/me/sessions/${AUTHKIT_REVOKE_JTI}")"
  assert_status "200" "${revoke_status}" "session revoke"
else
  echo "SKIP: set AUTHKIT_REVOKE_JTI to exercise session revocation."
fi
