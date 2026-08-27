#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
  echo "Usage: $0 IMAGE_REF OUTPUT_DIRECTORY REQUIRE_ALL(true|false)" >&2
  exit 2
fi

image_ref="$1"
output_dir="$2"
require_all="$3"
mkdir -p "${output_dir}"

missing=()
run_or_record() {
  local tool="$1"
  shift
  if command -v "${tool}" >/dev/null 2>&1; then
    "$@"
  else
    missing+=("${tool}")
    printf 'NOT PROVEN: required tool is unavailable: %s\n' "${tool}" \
      >"${output_dir}/${tool}-NOT-PROVEN.txt"
  fi
}

run_or_record trivy trivy fs --exit-code 1 --severity HIGH,CRITICAL \
  --ignore-unfixed --format json --output "${output_dir}/trivy-filesystem.json" .
run_or_record trivy trivy image --exit-code 1 --severity HIGH,CRITICAL \
  --ignore-unfixed --format json --output "${output_dir}/trivy-image.json" "${image_ref}"
run_or_record gitleaks gitleaks detect --no-banner --redact \
  --report-format json --report-path "${output_dir}/gitleaks.json" --source .
run_or_record semgrep semgrep scan --config auto --error --json \
  --output "${output_dir}/semgrep.json" .
run_or_record checkov checkov --directory . --quiet --output json \
  --output-file-path "${output_dir}/checkov.json"
run_or_record hadolint hadolint --format json Dockerfile

printf '%s\n' "${missing[@]:-}" | sed '/^$/d' >"${output_dir}/missing-tools.txt"
if [[ "${require_all}" == true && ${#missing[@]} -gt 0 ]]; then
  echo "NOT PROVEN: blocking scan tools missing: ${missing[*]}" >&2
  exit 1
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Scan gate remains NOT PROVEN; missing tools: ${missing[*]}"
else
  echo "Configured local scanners completed. Review reports before changing the gate."
fi
