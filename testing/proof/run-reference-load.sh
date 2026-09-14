#!/usr/bin/env bash
set -euo pipefail

duration="${K6_DURATION:-4h}"
vus="${K6_VUS:-4}"
target_rps="${K6_TARGET_RPS:-0.8}"
login_stagger_seconds="${K6_LOGIN_STAGGER_SECONDS:-4}"
base_url="${AUTHKIT_BASE_URL:-}"
introspection_url="${AUTHKIT_INTROSPECTION_URL:-}"
report_dir="${PROOF_REPORT_DIR:-}"
load_email="${AUTHKIT_K6_LOGIN_EMAIL:-}"
load_password="${AUTHKIT_K6_LOGIN_PASSWORD:-}"
worker_token="${AUTHKIT_WORKER_TOKEN:-}"

[[ -z "${load_email}" && -n "${AUTHKIT_K6_LOGIN_EMAIL_FILE:-}" ]] \
  && load_email="$(<"${AUTHKIT_K6_LOGIN_EMAIL_FILE}")"
[[ -z "${load_password}" && -n "${AUTHKIT_K6_LOGIN_PASSWORD_FILE:-}" ]] \
  && load_password="$(<"${AUTHKIT_K6_LOGIN_PASSWORD_FILE}")"
[[ -z "${worker_token}" && -n "${AUTHKIT_WORKER_TOKEN_FILE:-}" ]] \
  && worker_token="$(<"${AUTHKIT_WORKER_TOKEN_FILE}")"

if [[ -z "${base_url}" || -z "${introspection_url}" || -z "${report_dir}" \
      || -z "${load_email}" || -z "${load_password}" || -z "${worker_token}" ]]; then
  echo "FAIL: base URL, private introspection URL, report directory, load credentials and worker token are required." >&2
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
  AUTHKIT_BASE_URL="${base_url}" \
    AUTHKIT_INTROSPECTION_URL="${introspection_url}" \
    AUTHKIT_WORKER_TOKEN="${worker_token}" \
    AUTHKIT_K6_LOGIN_EMAIL="${load_email}" \
    AUTHKIT_K6_LOGIN_PASSWORD="${load_password}" \
    K6_DURATION="${duration}" K6_VUS="${vus}" K6_TARGET_RPS="${target_rps}" \
    K6_LOGIN_STAGGER_SECONDS="${login_stagger_seconds}" \
    k6 run --summary-export "${summary}" --out "json=${raw}" \
    testing/proof/k6/mixed-auth-workload.js
else
  command -v docker >/dev/null 2>&1 || { echo "FAIL: k6 or docker is required." >&2; exit 1; }
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  docker_host_args=()
  docker_ip_args=()
  if [[ -n "${AUTHKIT_LOAD_HOST_ALIAS:-}" ]]; then
    docker_host_args+=(--add-host "${AUTHKIT_LOAD_HOST_ALIAS}")
  fi
  if [[ -n "${AUTHKIT_LOAD_DOCKER_IP:-}" ]]; then
    docker_ip_args+=(--ip "${AUTHKIT_LOAD_DOCKER_IP}")
  fi
  docker run --rm --network "${AUTHKIT_LOAD_DOCKER_NETWORK:-host}" --user "$(id -u):$(id -g)" \
    "${docker_host_args[@]}" "${docker_ip_args[@]}" \
    -e AUTHKIT_BASE_URL="${base_url}" \
    -e AUTHKIT_K6_LOGIN_EMAIL="${load_email}" \
    -e AUTHKIT_K6_LOGIN_PASSWORD="${load_password}" \
    -e AUTHKIT_INTROSPECTION_URL="${introspection_url}" \
    -e AUTHKIT_WORKER_TOKEN="${worker_token}" \
    -e K6_INSECURE_SKIP_TLS_VERIFY="${K6_INSECURE_SKIP_TLS_VERIFY:-false}" \
    -e K6_DURATION="${duration}" -e K6_VUS="${vus}" -e K6_TARGET_RPS="${target_rps}" \
    -e K6_LOGIN_STAGGER_SECONDS="${login_stagger_seconds}" \
    -v "${repo_root}:/work:ro" -v "$(realpath "${report_dir}"):/evidence" \
    -w /work grafana/k6:0.57.0@sha256:70af91f86cd8e142e0544a4edaf79835a80033f71974b92edd5ac36fd4442a7b run \
    --summary-export /evidence/mixed-auth-summary.json \
    --out json=/evidence/mixed-auth-points.json \
    testing/proof/k6/mixed-auth-workload.js
fi

echo "Load harness completed. Correlate its results with host/JVM/PostgreSQL/Redis/outbox metrics before changing Gates 10 or 12."
