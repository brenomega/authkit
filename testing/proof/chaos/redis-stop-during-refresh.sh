#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: refresh returns a controlled 401/503 and never exposes token state.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements
require_compose

echo "Stopping Redis service for ${AUTHKIT_CHAOS_SECONDS:-10}s during refresh proof."
compose stop redis
sleep "${AUTHKIT_CHAOS_SECONDS:-10}"
compose start redis
echo "Redis restarted. Verify refresh behavior and session metrics."
