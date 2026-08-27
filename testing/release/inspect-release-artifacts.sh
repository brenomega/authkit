#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--jar PATH] [--image IMAGE] [--context]" >&2
}

jar_path=""
image_ref=""
inspect_context=false

while (($# > 0)); do
  case "$1" in
    --jar)
      jar_path="${2:-}"
      shift 2
      ;;
    --image)
      image_ref="${2:-}"
      shift 2
      ;;
    --context)
      inspect_context=true
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${jar_path}" && -z "${image_ref}" && "${inspect_context}" != true ]]; then
  usage
  exit 2
fi

task_tmp_dir="$(mktemp -d)"
container_id=""
cleanup() {
  if [[ -n "${container_id}" ]]; then
    docker rm -f "${container_id}" >/dev/null 2>&1 || true
  fi
  rm -rf "${task_tmp_dir}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

inspect_jar() {
  local candidate
  candidate="$(realpath "$1")"
  local listing="${task_tmp_dir}/jar-listing.txt"
  local extracted="${task_tmp_dir}/jar"

  [[ -f "${candidate}" ]] || fail "JAR not found: ${candidate}"
  jar tf "${candidate}" >"${listing}"
  if grep -Eiq '(^|/)(application-test\.(yml|yaml|properties)|test-keys/|[^/]+\.(key|pem))$' "${listing}"; then
    grep -Ei '(^|/)(application-test\.(yml|yaml|properties)|test-keys/|[^/]+\.(key|pem))$' "${listing}" >&2
    fail "test profile or private-key material is present in ${candidate}"
  fi

  mkdir -p "${extracted}"
  (cd "${extracted}" && jar xf "${candidate}")
  if grep -aRIl --exclude='*.class' -- '-----BEGIN .*PRIVATE KEY-----' "${extracted}" | grep -q .; then
    fail "private-key marker is present in ${candidate}"
  fi
  echo "PASS: JAR contains no test profile, test key, or private-key marker: ${candidate}"
}

if [[ "${inspect_context}" == true ]]; then
  context_dir="${task_tmp_dir}/context-output"
  mkdir -p "${context_dir}"
  docker build --target build-context --output "type=local,dest=${context_dir}" . >/dev/null
  context_root="${context_dir}/context"
  [[ -d "${context_root}" ]] || fail "Docker build-context export was not produced"
  for forbidden in .git .env src/test src/main/resources/application-test.yml src/main/resources/test-keys; do
    [[ ! -e "${context_root}/${forbidden}" ]] || fail "forbidden build-context path present: ${forbidden}"
  done
  if find "${context_root}" -type f \( -name '*.key' -o -name '*.pem' -o -name 'application-test.yml' \) -print -quit | grep -q .; then
    fail "private-key or test-profile file is present in the Docker build context"
  fi
  echo "PASS: Docker build context excludes tests, local secrets, private keys, and test profiles"
fi

if [[ -n "${jar_path}" ]]; then
  inspect_jar "${jar_path}"
fi

if [[ -n "${image_ref}" ]]; then
  image_root="${task_tmp_dir}/image-root"
  image_tar="${task_tmp_dir}/image.tar"
  mkdir -p "${image_root}"
  container_id="$(docker create "${image_ref}")"
  docker export --output "${image_tar}" "${container_id}"
  tar -xf "${image_tar}" -C "${image_root}"
  if find "${image_root}" -type f \( -name 'application-test.yml' -o -name 'application-test.yaml' -o -name 'application-test.properties' -o -name '*.key' \) -print -quit | grep -q .; then
    fail "private-key or test-profile file is present in image ${image_ref}"
  fi
  image_jar="${image_root}/app/app.jar"
  [[ -n "${image_jar}" ]] || fail "application JAR not found in image ${image_ref}"
  [[ -f "${image_jar}" ]] || fail "application JAR not found at /app/app.jar in image ${image_ref}"
  inspect_jar "${image_jar}"
  echo "PASS: image contains no test profile or private-key material: ${image_ref}"
fi
