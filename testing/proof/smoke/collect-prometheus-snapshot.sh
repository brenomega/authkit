#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/smoke/lib.sh
source "${script_dir}/lib.sh"

require_env AUTHKIT_BASE_URL
refuse_production "${AUTHKIT_BASE_URL}"

report_dir="${PROOF_REPORT_DIR:-target/proof/$(date -u +%Y%m%dT%H%M%SZ)}"
label="${PROOF_SNAPSHOT_LABEL:-snapshot}"
mkdir -p "${report_dir}"

curl --silent --show-error --fail "${AUTHKIT_BASE_URL}/actuator/prometheus" > "${report_dir}/prometheus-${label}.txt"

grep -E '^(http_server_requests|hikaricp_|jvm_memory_|process_cpu_|security_|authkit_|resilience4j_|rabbitmq_|executor_)' \
  "${report_dir}/prometheus-${label}.txt" > "${report_dir}/prometheus-${label}-important.txt" || true

echo "PASS: wrote Prometheus snapshot ${report_dir}/prometheus-${label}.txt"
