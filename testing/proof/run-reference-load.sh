#!/usr/bin/env bash
set -euo pipefail

duration="${K6_DURATION:-4h}"
vus="${K6_VUS:-10}"
base_url="${AUTHKIT_BASE_URL:-}"
report_dir="${PROOF_REPORT_DIR:-}"

if [[ -z "${base_url}" || -z "${report_dir}" ]]; then
  echo "FAIL: AUTHKIT_BASE_URL and PROOF_REPORT_DIR are required." >&2
  exit 1
fi
case "${duration}" in
  4h|[5-9]h|[1-9][0-9]h) ;;
  *)
    if [[ "${ALLOW_SHORT_LOAD_PROOF:-false}" != true ]]; then
      echo "FAIL: release proof requires K6_DURATION of at least 4h; set ALLOW_SHORT_LOAD_PROOF=true only for harness validation." >&2
      exit 1
    fi
    ;;
esac

mkdir -p "${report_dir}"
summary="${report_dir}/mixed-auth-summary.json"
raw="${report_dir}/mixed-auth-points.json"

if command -v k6 >/dev/null 2>&1; then
  AUTHKIT_BASE_URL="${base_url}" K6_DURATION="${duration}" K6_VUS="${vus}" \
    k6 run --summary-export "${summary}" --out "json=${raw}" \
    testing/proof/k6/mixed-auth-workload.js
else
  command -v docker >/dev/null 2>&1 || { echo "FAIL: k6 or docker is required." >&2; exit 1; }
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  docker_host_args=()
  if [[ -n "${AUTHKIT_LOAD_HOST_ALIAS:-}" ]]; then
    docker_host_args+=(--add-host "${AUTHKIT_LOAD_HOST_ALIAS}")
  fi
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    "${docker_host_args[@]}" \
    -e AUTHKIT_BASE_URL="${base_url}" \
    -e AUTHKIT_K6_LOGIN_EMAIL="${AUTHKIT_K6_LOGIN_EMAIL:-}" \
    -e AUTHKIT_K6_LOGIN_PASSWORD="${AUTHKIT_K6_LOGIN_PASSWORD:-}" \
    -e AUTHKIT_ACCESS_TOKEN="${AUTHKIT_ACCESS_TOKEN:-}" \
    -e K6_INSECURE_SKIP_TLS_VERIFY="${K6_INSECURE_SKIP_TLS_VERIFY:-false}" \
    -e K6_DURATION="${duration}" -e K6_VUS="${vus}" \
    -v "${repo_root}:/work:ro" -v "$(realpath "${report_dir}"):/evidence" \
    -w /work grafana/k6:0.57.0 run \
    --summary-export /evidence/mixed-auth-summary.json \
    --out json=/evidence/mixed-auth-points.json \
    testing/proof/k6/mixed-auth-workload.js
fi

echo "Load harness completed. Correlate its results with host/JVM/PostgreSQL/Redis/outbox metrics before changing Gates 10 or 12."
