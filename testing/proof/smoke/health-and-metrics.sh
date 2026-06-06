#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"

health_status="$(curl --silent --show-error --output /tmp/authkit-health.json --write-out '%{http_code}' "${AUTHKIT_BASE_URL}/actuator/health")"
assert_status "200" "${health_status}" "health endpoint"

metrics_status="$(curl --silent --show-error --output /tmp/authkit-prometheus.txt --write-out '%{http_code}' "${AUTHKIT_BASE_URL}/actuator/prometheus")"
assert_status "200" "${metrics_status}" "prometheus endpoint"

echo "PASS: health and metrics endpoints are reachable."
