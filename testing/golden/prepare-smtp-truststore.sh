#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 LOCAL_CA_CERTIFICATE OUTPUT_TRUSTSTORE" >&2
  exit 64
fi

ca_certificate="$1"
output_truststore="$2"

if [[ ! -r "${ca_certificate}" ]]; then
  echo "Local CA certificate is not readable: ${ca_certificate}" >&2
  exit 1
fi

temporary_directory="$(mktemp -d)"
container_name="authkit-truststore-$RANDOM-$$"
cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  rm -rf "${temporary_directory}"
}
trap cleanup EXIT

# Begin with the same public CA set used by the candidate runtime. Importing
# only the local SMTP CA would break HTTPS dependencies such as HIBP.
docker create --name "${container_name}" eclipse-temurin:21-jre-alpine true >/dev/null
docker cp "${container_name}:/opt/java/openjdk/lib/security/cacerts" \
  "${temporary_directory}/combined-cacerts"

keytool -importcert -noprompt -trustcacerts \
  -alias authkit-local-smtp-proof-ca \
  -file "${ca_certificate}" \
  -keystore "${temporary_directory}/combined-cacerts" \
  -storepass changeit >/dev/null

install -m 0444 "${temporary_directory}/combined-cacerts" "${output_truststore}"
echo "Combined JVM public CAs and local SMTP proof CA in ${output_truststore}"
