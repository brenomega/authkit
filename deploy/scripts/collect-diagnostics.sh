#!/usr/bin/env bash
set -euo pipefail
umask 077

report_dir="${AUTHKIT_DIAGNOSTICS_DIR:-target/diagnostics/$(date -u +%Y%m%dT%H%M%SZ)}"
base_url="${AUTHKIT_BASE_URL:-http://localhost:8080}"
mkdir -p "${report_dir}"
chmod 700 "${report_dir}"

mask_env() {
  env | sort | awk -F= '
    {
      key=$1
      if (toupper(key) ~ /(PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE|PEPPER|KEY|CREDENTIAL|AUTHORIZATION|COOKIE|DSN)/) {
        print key "=****"
      } else {
        print $0
      }
    }'
}

{
  echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  git rev-parse HEAD 2>/dev/null | sed 's/^/git_commit=/' || true
  git status --short 2>/dev/null | sed 's/^/git_status=/' || true
  java -version 2>&1 | sed 's/^/java=/' || true
} > "${report_dir}/summary.txt"

mask_env > "${report_dir}/environment-masked.txt"

curl --silent --show-error --max-time 5 "${base_url}/actuator/health" > "${report_dir}/health.json" || true
curl --silent --show-error --max-time 5 "${base_url}/actuator/prometheus" > "${report_dir}/prometheus.txt" || true

if [[ -n "${AUTHKIT_LOG_PATH:-}" && -r "${AUTHKIT_LOG_PATH}" ]]; then
  tail -n "${AUTHKIT_LOG_LINES:-200}" "${AUTHKIT_LOG_PATH}" > "${report_dir}/recent-logs.txt"
fi

echo "Diagnostics written to ${report_dir}. Review files for accidental sensitive data before sharing."
