#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: Redis-backed login either succeeds before interruption or returns an opaque controlled error.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements
require_compose

echo "Stopping Redis service for ${AUTHKIT_CHAOS_SECONDS:-10}s during login proof."
compose stop redis
sleep "${AUTHKIT_CHAOS_SECONDS:-10}"
compose start redis
echo "Redis restarted. Run health-and-metrics and inspect Redis degradation metrics."
