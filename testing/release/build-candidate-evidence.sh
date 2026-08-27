#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--multiarch] [--require-scans]" >&2
}

build_multiarch=false
require_scans=false
while (($# > 0)); do
  case "$1" in
    --multiarch) build_multiarch=true ;;
    --require-scans) require_scans=true ;;
    *) usage; exit 2 ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

task_tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${task_tmp_dir}"
}
trap cleanup EXIT

candidate_version="$(./mvnw help:evaluate -Dexpression=project.version -q -DforceStdout)"
candidate_tag="authkit-local:${candidate_version}"
verify_log="${task_tmp_dir}/maven-clean-verify.log"
sample_log="${task_tmp_dir}/resource-server-test.log"

./mvnw clean verify -Dspring.profiles.active=test -B 2>&1 | tee "${verify_log}"

evidence_dir="${repo_root}/target/release-evidence"
mkdir -p "${evidence_dir}/sbom" "${evidence_dir}/scans"
cp "${verify_log}" "${evidence_dir}/maven-clean-verify.log"

(
  cd samples/resource-server-spring
  ../../mvnw test -B 2>&1 | tee "${sample_log}"
)
cp "${sample_log}" "${evidence_dir}/resource-server-test.log"
node --check samples/first-party-same-site/app.js
node --check samples/oauth-cross-site/app.js
testing/release/check-documentation.py

jar_path="$(find target -maxdepth 1 -type f -name 'authkit-*.jar' ! -name '*.original' -print -quit)"
testing/release/inspect-release-artifacts.sh --jar "${jar_path}" --context \
  2>&1 | tee "${evidence_dir}/artifact-inspection.log"

docker build --label "org.opencontainers.image.version=${candidate_version}" \
  --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
  --tag "${candidate_tag}" . 2>&1 | tee "${evidence_dir}/docker-build.log"
testing/release/inspect-release-artifacts.sh --image "${candidate_tag}" \
  2>&1 | tee "${evidence_dir}/image-inspection.log"

cp target/bom.json target/bom.xml "${evidence_dir}/sbom/"
git diff --binary >"${evidence_dir}/tracked.patch"
git ls-files --others --exclude-standard -z \
  | sort -z \
  | xargs -0 -r sha256sum >"${evidence_dir}/untracked-files.sha256"
git status --short >"${evidence_dir}/git-status.txt"

head_commit="$(git rev-parse HEAD)"
branch="$(git branch --show-current)"
tracked_patch_sha256="$(sha256sum "${evidence_dir}/tracked.patch" | cut -d' ' -f1)"
untracked_manifest_sha256="$(sha256sum "${evidence_dir}/untracked-files.sha256" | cut -d' ' -f1)"
image_id="$(docker image inspect --format '{{.Id}}' "${candidate_tag}")"

jq -n \
  --arg candidateVersion "${candidate_version}" \
  --arg branch "${branch}" \
  --arg headCommit "${head_commit}" \
  --arg trackedPatchSha256 "${tracked_patch_sha256}" \
  --arg untrackedManifestSha256 "${untracked_manifest_sha256}" \
  --arg localImageReference "${candidate_tag}" \
  --arg localImageId "${image_id}" \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    schema: "authkit-release-evidence/v1",
    candidateVersion: $candidateVersion,
    source: {
      branch: $branch,
      headCommit: $headCommit,
      trackedPatchSha256: $trackedPatchSha256,
      untrackedManifestSha256: $untrackedManifestSha256
    },
    image: {
      status: "local-single-platform-only",
      reference: $localImageReference,
      immutableLocalId: $localImageId,
      publishedDigest: null
    },
    generatedAt: $generatedAt,
    releaseAuthorization: false
  }' >"${evidence_dir}/manifest.json"

jq -n \
  --arg subjectName "authkit-${candidate_version}-source-tree" \
  --arg subjectDigest "${tracked_patch_sha256}" \
  --arg headCommit "${head_commit}" \
  --arg localImageId "${image_id#sha256:}" \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    _type: "https://in-toto.io/Statement/v1",
    subject: [{name: $subjectName, digest: {sha256: $subjectDigest}}],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/brenomega/authkit/local-candidate-build/v1",
        externalParameters: {publicationAuthorized: false},
        internalParameters: {headCommit: $headCommit},
        resolvedDependencies: [{uri: ("git+https://github.com/brenomega/authkit@" + $headCommit), digest: {gitCommit: $headCommit}}]
      },
      runDetails: {
        builder: {id: "https://github.com/brenomega/authkit/testing/release/build-candidate-evidence.sh"},
        metadata: {invocationId: $generatedAt, startedOn: $generatedAt, finishedOn: $generatedAt},
        byproducts: [{name: "local-image", digest: {sha256: $localImageId}}]
      }
    }
  }' >"${evidence_dir}/unsigned-provenance.json"

if [[ "${build_multiarch}" == true ]]; then
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --label "org.opencontainers.image.version=${candidate_version}" \
    --label "org.opencontainers.image.revision=${head_commit}" \
    --output "type=oci,dest=${evidence_dir}/authkit-${candidate_version}.oci.tar" \
    --metadata-file "${evidence_dir}/multiarch-metadata.json" . \
    2>&1 | tee "${evidence_dir}/multiarch-build.log"

  multiarch_digest="$(jq -r '."containerimage.digest"' "${evidence_dir}/multiarch-metadata.json")"
  manifest_update="${task_tmp_dir}/manifest-multiarch.json"
  jq \
    --arg digest "${multiarch_digest}" \
    --arg archive "authkit-${candidate_version}.oci.tar" \
    '.image.status = "local-single-platform-plus-multiarch-oci"
     | .image.multiarchOci = {
         archive: $archive,
         digest: $digest,
         platforms: ["linux/amd64", "linux/arm64"],
         published: false
       }' \
    "${evidence_dir}/manifest.json" >"${manifest_update}"
  mv "${manifest_update}" "${evidence_dir}/manifest.json"
fi

testing/release/scan-candidate.sh "${candidate_tag}" "${evidence_dir}/scans" "${require_scans}"

(
  cd "${evidence_dir}"
  find . -type f ! -name checksums.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum >checksums.sha256
)

echo "Candidate evidence created at ${evidence_dir}"
echo "No image, artifact, tag, signature, or attestation was published."
