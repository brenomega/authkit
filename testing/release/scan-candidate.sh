#!/usr/bin/env bash
set -euo pipefail

if (($# < 3 || $# > 4)); then
  echo "Usage: $0 IMAGE_REF OUTPUT_DIRECTORY REQUIRE_ALL(true|false) [SOURCE_ARCHIVE_OR_DIRECTORY]" >&2
  exit 2
fi

image_ref="$1"
output_dir="$(mkdir -p "$2" && realpath "$2")"
require_all="$3"
source_input="${4:-.}"

trivy_image="aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854"
semgrep_image="semgrep/semgrep@sha256:62aaded52737fc401299d994f29fcd3d4049bd90bbb77407eca2e29e51ab0d98"
checkov_image="bridgecrew/checkov@sha256:b62188361e833172ee157251672ef31a8fcffd78e28211d34d761c8ecbe024cf"
hadolint_image="hadolint/hadolint@sha256:7aba693c1442eb31c0b015c129697cb3b6cb7da589d85c7562f9deb435a6657c"
ownership_helper_image="eclipse-temurin:21-jre-alpine@sha256:974b08960c5d96694c780e65b2d5705268ab1e1ca1a0dd0caf4ba6c3fe34d699"

command -v docker >/dev/null 2>&1 || {
  echo "NOT PROVEN: Docker is required for the pinned release scanners." >&2
  exit 1
}

task_tmp_dir="$(mktemp -d)"
cleanup() {
  docker run --rm -v "${output_dir}:/out" "${ownership_helper_image}" \
    chown -R "$(id -u):$(id -g)" /out >/dev/null 2>&1 || true
  rm -rf "${task_tmp_dir}"
}
trap cleanup EXIT

if [[ -d "${source_input}" ]]; then
  source_root="$(realpath "${source_input}")"
elif [[ -f "${source_input}" ]]; then
  mkdir -p "${task_tmp_dir}/source"
  tar -xzf "${source_input}" -C "${task_tmp_dir}/source"
  source_root="$(find "${task_tmp_dir}/source" -mindepth 1 -maxdepth 1 -type d -print -quit)"
  [[ -n "${source_root}" ]] || { echo "FAIL: source archive has no root directory." >&2; exit 1; }
else
  echo "FAIL: source input does not exist: ${source_input}" >&2
  exit 1
fi

scanner_images=("${trivy_image}" "${gitleaks_image}" "${semgrep_image}" "${checkov_image}" "${hadolint_image}" "${ownership_helper_image}")
{
  printf 'captured_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for scanner_image in "${scanner_images[@]}"; do
    docker image inspect --format '{{index .RepoDigests 0}} image_id={{.Id}}' "${scanner_image}"
  done
  docker run --rm "${trivy_image}" --version
  docker run --rm "${gitleaks_image}" version
  docker run --rm "${semgrep_image}" semgrep --version
  docker run --rm "${checkov_image}" --version
  docker run --rm "${hadolint_image}" hadolint --version
} >"${output_dir}/scanner-versions.txt" 2>&1

failures=()
run_scan() {
  local name="$1"
  shift
  if ! "$@" >"${output_dir}/${name}.stdout.log" 2>"${output_dir}/${name}.stderr.log"; then
    failures+=("${name}")
  fi
}

run_scan trivy-filesystem-vulnerability docker run --rm \
  -v authkit-trivy-cache-v066:/root/.cache/trivy \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${trivy_image}" fs --scanners vuln --exit-code 1 --severity HIGH,CRITICAL \
  --ignorefile /src/.trivyignore.yaml \
  --format json --output /out/trivy-filesystem-vulnerability.json /src

run_scan trivy-filesystem-secret docker run --rm \
  -v authkit-trivy-cache-v066:/root/.cache/trivy \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${trivy_image}" fs --scanners secret --exit-code 1 --severity HIGH,CRITICAL \
  --ignorefile /src/.trivyignore.yaml --format json --output /out/trivy-filesystem-secret.json /src

run_scan trivy-misconfiguration docker run --rm \
  -v authkit-trivy-cache-v066:/root/.cache/trivy \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${trivy_image}" config --exit-code 1 --severity HIGH,CRITICAL \
  --ignorefile /src/.trivyignore.yaml --format json --output /out/trivy-misconfiguration.json /src

run_scan trivy-image docker run --rm \
  -v authkit-trivy-cache-v066:/root/.cache/trivy \
  -v /var/run/docker.sock:/var/run/docker.sock -v "${output_dir}:/out" \
  "${trivy_image}" image --scanners vuln --exit-code 1 --severity HIGH,CRITICAL \
  --format json --output /out/trivy-image.json "${image_ref}"

run_scan gitleaks docker run --rm \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${gitleaks_image}" detect --no-git --no-banner --redact \
  --config /src/.gitleaks.toml --report-format json --report-path /out/gitleaks.json --source /src

run_scan semgrep docker run --rm \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${semgrep_image}" semgrep scan --config auto --error --json \
  --exclude target --exclude .git --output /out/semgrep.json /src

run_scan checkov docker run --rm \
  -v "${source_root}:/src:ro" -v "${output_dir}:/out" \
  "${checkov_image}" --directory /src --framework dockerfile kubernetes github_actions \
  --quiet --output json --output-file-path /out/checkov-results
cp "${output_dir}/checkov-results/results_json.json" "${output_dir}/checkov.json"

run_scan hadolint docker run --rm \
  -v "${source_root}:/src:ro" "${hadolint_image}" hadolint --format json /src/Dockerfile
cp "${output_dir}/hadolint.stdout.log" "${output_dir}/hadolint.json"

printf '%s\n' "${failures[@]:-}" | sed '/^$/d' >"${output_dir}/failed-scanners.txt"
if ((${#failures[@]} > 0)); then
  echo "Scan findings or execution failures require review: ${failures[*]}" >&2
  if [[ "${require_all}" == true ]]; then
    exit 1
  fi
else
  echo "All pinned candidate scanners completed without blocking findings."
fi
