#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tier=""
backend=""
email_provider=""
run_load="false"
run_chaos="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="${2:-}"; shift 2 ;;
    --backend) backend="${2:-}"; shift 2 ;;
    --email-provider) email_provider="${2:-}"; shift 2 ;;
    --load) run_load="${2:-false}"; shift 2 ;;
    --chaos) run_chaos="${2:-false}"; shift 2 ;;
    *)
      echo "FAIL: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${tier}" || -z "${backend}" || -z "${email_provider}" ]]; then
  echo "Usage: testing/proof/run-proof.sh --tier <tier> --backend <redis|jdbc> --email-provider <smtp|resend> [--load true] [--chaos true]" >&2
  exit 1
fi
if [[ -z "${AUTHKIT_BASE_URL:-}" ]]; then
  echo "FAIL: AUTHKIT_BASE_URL is required." >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_dir="docs/proof/reports/${timestamp}-${tier}-${backend}"
mkdir -p "${report_dir}"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
dirty="$(git status --short 2>/dev/null || true)"
{
  echo "timestamp=${timestamp}"
  echo "tier=${tier}"
  echo "backend=${backend}"
  echo "email_provider=${email_provider}"
  echo "commit=${commit}"
  if [[ -n "${dirty}" ]]; then
    echo "dirty_tree=true"
    printf '%s\n' "${dirty}"
  else
    echo "dirty_tree=false"
  fi
} > "${report_dir}/run-summary.txt"

echo "Proof report directory: ${report_dir}"
echo "Commit: ${commit}"
if [[ -n "${dirty}" ]]; then
  echo "Working tree has uncommitted changes; report records this."
fi

PROOF_REPORT_DIR="${report_dir}" PROOF_SNAPSHOT_LABEL=before testing/proof/smoke/collect-prometheus-snapshot.sh || true

smoke_scripts=(
  testing/proof/smoke/health-and-metrics.sh
  testing/proof/smoke/register-confirm-login-refresh-logout.sh
  testing/proof/smoke/password-recovery-reset.sh
  testing/proof/smoke/mfa-login.sh
  testing/proof/smoke/session-list-revoke.sh
  testing/proof/smoke/oauth-code-token-userinfo.sh
)

for script in "${smoke_scripts[@]}"; do
  echo "Running ${script}"
  "${script}" | tee "${report_dir}/$(basename "${script}" .sh).log"
done

if [[ -d target/contract-fixtures ]]; then
  testing/proof/smoke/negative-contracts.sh | tee "${report_dir}/negative-contracts.log"
else
  echo "SKIP: target/contract-fixtures is missing; run testing/proof/fixtures/generate-test-tokens.sh for negative contracts." | tee "${report_dir}/negative-contracts.log"
fi

if [[ "${run_load}" == "true" ]]; then
  if ! command -v k6 >/dev/null 2>&1; then
    echo "FAIL: --load true requested but k6 is not installed." >&2
    exit 1
  fi
  for scenario in testing/proof/k6/*.js; do
    echo "Running k6 ${scenario}"
    k6 run "${scenario}" | tee "${report_dir}/$(basename "${scenario}" .js).k6.log"
  done
fi

if [[ "${run_chaos}" == "true" ]]; then
  for script in testing/proof/chaos/*.sh; do
    [[ "$(basename "${script}")" == "lib-chaos.sh" ]] && continue
    echo "Running chaos ${script}"
    "${script}" | tee "${report_dir}/$(basename "${script}" .sh).log"
  done
fi

PROOF_REPORT_DIR="${report_dir}" PROOF_SNAPSHOT_LABEL=after testing/proof/smoke/collect-prometheus-snapshot.sh || true

cp docs/proof/templates/proof-report-template.md "${report_dir}/proof-report.md"
echo "Complete the report template at ${report_dir}/proof-report.md"
