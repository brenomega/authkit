#!/usr/bin/env bash
set -euo pipefail

if (($# != 2)); then
  echo "Usage: $0 EVIDENCE_DIRECTORY COSIGN_PRIVATE_KEY" >&2
  exit 2
fi

evidence_dir="$(realpath "$1")"
signing_key="$(realpath "$2")"
[[ -f "${evidence_dir}/checksums.sha256" ]] || { echo "checksums.sha256 missing" >&2; exit 1; }
[[ -f "${signing_key}" ]] || { echo "signing key missing" >&2; exit 1; }
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }

# This signs the local evidence manifest only. An OCI registry signature and
# attestation must later target the immutable published digest under explicit
# maintainer authorization; this script never pushes or mutates a registry.
cosign sign-blob --yes --key "${signing_key}" \
  --output-signature "${evidence_dir}/checksums.sha256.sig" \
  "${evidence_dir}/checksums.sha256"
echo "Signed local evidence checksums. No OCI image or registry was modified."
