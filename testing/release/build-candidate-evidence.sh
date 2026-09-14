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
audit_report="authkit-v0.1-final-audit-v5-reviewed.md"
cleanup() {
  rm -rf "${task_tmp_dir}"
}
trap cleanup EXIT

candidate_version="$(./mvnw help:evaluate -Dexpression=project.version -q -DforceStdout)"
candidate_tag="authkit-local:${candidate_version}"
verify_log="${task_tmp_dir}/maven-clean-verify.log"
sample_log="${task_tmp_dir}/resource-server-test.log"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Maven clean removes target. Preserve prior candidate evidence and remediation
# transcripts outside that directory; never silently overwrite an earlier proof.
if [[ -d target/release-evidence || -d target/remediation-v5 ]]; then
  mkdir -p "${repo_root}/.release-evidence-history"
  evidence_history="$(mktemp -d "${repo_root}/.release-evidence-history/candidate.XXXXXX")"
  for previous in target/release-evidence target/remediation-v5 target/surefire-reports; do
    if [[ -d "${previous}" ]]; then cp -a "${previous}" "${evidence_history}/"; fi
  done
  echo "previous_evidence_preserved_at=${evidence_history}"
fi

./mvnw clean verify -Dspring.profiles.active=test -B 2>&1 | tee "${verify_log}"

evidence_dir="${repo_root}/target/release-evidence"
mkdir -p "${evidence_dir}/sbom" "${evidence_dir}/scans"
cp "${verify_log}" "${evidence_dir}/maven-clean-verify.log"

{
  echo "captured_at_utc=${started_at}"
  java -version
  ./mvnw -version
  docker version
  docker buildx version
  node --version
} >"${evidence_dir}/tool-versions.txt" 2>&1

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

head_commit="$(git rev-parse HEAD)"
branch="$(git branch --show-current)"
source_date_epoch="$(git show -s --format=%ct "${head_commit}")"
candidate_index="${task_tmp_dir}/candidate.index"
GIT_INDEX_FILE="${candidate_index}" git read-tree HEAD
GIT_INDEX_FILE="${candidate_index}" git add -A -- .
GIT_INDEX_FILE="${candidate_index}" git rm --cached --ignore-unmatch -- "${audit_report}" >/dev/null
candidate_tree="$(GIT_INDEX_FILE="${candidate_index}" git write-tree)"
git ls-tree -r --full-tree "${candidate_tree}" >"${evidence_dir}/candidate-tree-files.txt"

source_archive="${evidence_dir}/authkit-${candidate_version}-source.tar.gz"
git archive --format=tar --mtime="@${source_date_epoch}" \
  --prefix="authkit-${candidate_version}/" "${candidate_tree}" \
  | gzip -n >"${source_archive}"
source_archive_sha256="$(sha256sum "${source_archive}" | cut -d' ' -f1)"
candidate_context_parent="${task_tmp_dir}/candidate-context"
mkdir -p "${candidate_context_parent}"
tar -xzf "${source_archive}" -C "${candidate_context_parent}"
candidate_context="${candidate_context_parent}/authkit-${candidate_version}"
(
  cd "${candidate_context}"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"${evidence_dir}/source-files.sha256"
testing/release/inspect-release-artifacts.sh --context-dir "${candidate_context}" \
  2>&1 | tee "${evidence_dir}/frozen-context-inspection.log"

docker build --label "org.opencontainers.image.version=${candidate_version}" \
  --label "org.opencontainers.image.revision=${candidate_tree}" \
  --label "io.authkit.base-commit=${head_commit}" \
  --tag "${candidate_tag}" "${candidate_context}" 2>&1 | tee "${evidence_dir}/docker-build.log"
testing/release/inspect-release-artifacts.sh --image "${candidate_tag}" \
  2>&1 | tee "${evidence_dir}/image-inspection.log"

cp target/bom.json target/bom.xml "${evidence_dir}/sbom/"

resolved_images_file="${task_tmp_dir}/resolved-images.txt"
grep -RhoE '[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}' \
  Dockerfile deploy testing src/test \
  | sort -u >"${resolved_images_file}"
maven_distribution_url="$(sed -n 's/^distributionUrl=//p' .mvn/wrapper/maven-wrapper.properties)"
maven_distribution_sha256="$(sed -n 's/^distributionSha256Sum=//p' .mvn/wrapper/maven-wrapper.properties)"
jq -Rn \
  --arg mavenDistributionUrl "${maven_distribution_url}" \
  --arg mavenDistributionSha256 "${maven_distribution_sha256}" \
  --arg mavenWrapperJarSha256 "$(sha256sum .mvn/wrapper/maven-wrapper.jar | cut -d' ' -f1)" \
  --arg pomSha256 "$(sha256sum pom.xml | cut -d' ' -f1)" \
  --arg sbomSha256 "$(sha256sum target/bom.json | cut -d' ' -f1)" \
  '{
    mavenDistribution: {uri: $mavenDistributionUrl, digest: {sha256: $mavenDistributionSha256}},
    mavenWrapperJar: {uri: ".mvn/wrapper/maven-wrapper.jar", digest: {sha256: $mavenWrapperJarSha256}},
    projectModel: {uri: "pom.xml", digest: {sha256: $pomSha256}},
    resolvedDependencySbom: {uri: "target/bom.json", digest: {sha256: $sbomSha256}},
    externalImages: [inputs
      | select(length > 0)
      | capture("^(?<uri>.+)@sha256:(?<digest>[a-f0-9]{64})$")
      | {uri: .uri, digest: {sha256: .digest}}]
  }' <"${resolved_images_file}" >"${evidence_dir}/resolved-build-inputs.json"

git diff --binary -- . ":(exclude)${audit_report}" >"${evidence_dir}/tracked.patch"
git ls-files --others --exclude-standard -z -- . \
  ":(exclude)${audit_report}" \
  | sort -z \
  | xargs -0 -r sha256sum >"${evidence_dir}/untracked-files.sha256"
git status --short >"${evidence_dir}/git-status.txt"

tracked_patch_sha256="$(sha256sum "${evidence_dir}/tracked.patch" | cut -d' ' -f1)"
untracked_manifest_sha256="$(sha256sum "${evidence_dir}/untracked-files.sha256" | cut -d' ' -f1)"
image_id="$(docker image inspect --format '{{.Id}}' "${candidate_tag}")"

jq -n \
  --arg candidateVersion "${candidate_version}" \
  --arg branch "${branch}" \
  --arg headCommit "${head_commit}" \
  --arg candidateTree "${candidate_tree}" \
  --arg sourceArchive "$(basename "${source_archive}")" \
  --arg sourceArchiveSha256 "${source_archive_sha256}" \
  --argjson sourceDateEpoch "${source_date_epoch}" \
  --arg auditReport "${audit_report}" \
  --arg trackedPatchSha256 "${tracked_patch_sha256}" \
  --arg untrackedManifestSha256 "${untracked_manifest_sha256}" \
  --arg localImageReference "${candidate_tag}" \
  --arg localImageId "${image_id}" \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile resolvedBuildInputs "${evidence_dir}/resolved-build-inputs.json" \
  '{
    schema: "authkit-release-evidence/v1",
    candidateVersion: $candidateVersion,
    source: {
      branch: $branch,
      baseCommit: $headCommit,
      candidateTree: $candidateTree,
      archive: $sourceArchive,
      archiveSha256: $sourceArchiveSha256,
      sourceDateEpoch: $sourceDateEpoch,
      excludedEvidenceDocuments: [$auditReport],
      trackedPatchSha256: $trackedPatchSha256,
      untrackedManifestSha256: $untrackedManifestSha256
    },
    image: {
      status: "local-single-platform-only",
      reference: $localImageReference,
      immutableLocalId: $localImageId,
      publishedDigest: null
    },
    resolvedBuildInputs: $resolvedBuildInputs[0],
    generatedAt: $generatedAt,
    releaseAuthorization: false
  }' >"${evidence_dir}/manifest.json"

jq -n \
  --arg subjectName "authkit-${candidate_version}-source-tree" \
  --arg subjectDigest "${source_archive_sha256}" \
  --arg headCommit "${head_commit}" \
  --arg candidateTree "${candidate_tree}" \
  --arg localImageId "${image_id#sha256:}" \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile resolvedBuildInputs "${evidence_dir}/resolved-build-inputs.json" \
  '{
    _type: "https://in-toto.io/Statement/v1",
    subject: [{name: $subjectName, digest: {sha256: $subjectDigest}}],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/brenomega/authkit/local-candidate-build/v1",
        externalParameters: {publicationAuthorized: false},
        internalParameters: {baseCommit: $headCommit, candidateTree: $candidateTree},
        resolvedDependencies: ([
          {uri: ("git+https://github.com/brenomega/authkit@" + $headCommit), digest: {gitCommit: $headCommit}},
          $resolvedBuildInputs[0].mavenDistribution,
          $resolvedBuildInputs[0].mavenWrapperJar,
          $resolvedBuildInputs[0].projectModel,
          $resolvedBuildInputs[0].resolvedDependencySbom
        ] + $resolvedBuildInputs[0].externalImages)
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
    --label "org.opencontainers.image.revision=${candidate_tree}" \
    --label "io.authkit.base-commit=${head_commit}" \
    --output "type=oci,dest=${evidence_dir}/authkit-${candidate_version}.oci.tar" \
    --metadata-file "${evidence_dir}/multiarch-metadata.json" "${candidate_context}" \
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

  provenance_update="${task_tmp_dir}/provenance-multiarch.json"
  jq --arg digest "${multiarch_digest#sha256:}" \
    '.subject += [{name: "authkit-multiarch-oci", digest: {sha256: $digest}}]
     | .predicate.runDetails.byproducts += [{name: "multiarch-oci-manifest", digest: {sha256: $digest}}]' \
    "${evidence_dir}/unsigned-provenance.json" >"${provenance_update}"
  mv "${provenance_update}" "${evidence_dir}/unsigned-provenance.json"
fi

testing/release/scan-candidate.sh "${candidate_tag}" "${evidence_dir}/scans" "${require_scans}" "${source_archive}"

(
  cd "${evidence_dir}"
  find . -type f ! -name checksums.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum >checksums.sha256
)

echo "Candidate evidence created at ${evidence_dir}"
echo "Base commit: ${head_commit}"
echo "Candidate tree: ${candidate_tree}"
echo "Source archive SHA-256: ${source_archive_sha256}"
echo "No image, artifact, tag, signature, or attestation was published."
