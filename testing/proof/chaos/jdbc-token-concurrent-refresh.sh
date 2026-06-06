#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: JDBC token backend allows one refresh rotation and revokes the family on replay.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements

echo "Running JDBC concurrent refresh regression test as a local proof proxy."
./mvnw -Dspring.profiles.active=test -Dtest=io.github.brenomega.authkit.infrastructure.persistence.JdbcTokenStorageTest#concurrentRefreshReplayAllowsOneRotationAndRevokesFamily test
