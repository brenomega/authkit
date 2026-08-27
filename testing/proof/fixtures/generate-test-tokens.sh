#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

if [[ ! -f "${repo_root}/pom.xml" || ! -d "${repo_root}/src/test/resources/test-keys" ]]; then
  echo "FAIL: repository root could not be found from ${script_dir}" >&2
  exit 1
fi

key_dir="${repo_root}/src/test/resources/test-keys"
if [[ "${JWT_PRIVATE_KEY_PATH:-}" != "" ]]; then
  case "${JWT_PRIVATE_KEY_PATH}" in
    "${key_dir}"/*) ;;
    *)
      echo "FAIL: contract fixture generation may only use committed test keys." >&2
      echo "Refusing JWT_PRIVATE_KEY_PATH outside ${key_dir}." >&2
      exit 1
      ;;
  esac
fi

echo "WARNING: generated JWTs are test-only contract fixtures. Do not use them outside local/HML proof runs."
echo "Generating signed fixtures under target/contract-fixtures without printing token values."

cd "${repo_root}"
./mvnw -Dspring.profiles.active=test -Dtest=io.github.brenomega.authkit.testing.ContractFixtureTokenGeneratorTest test

echo "Generated:"
find "${repo_root}/target/contract-fixtures" -maxdepth 1 -type f -printf '  %f\n' | sort
