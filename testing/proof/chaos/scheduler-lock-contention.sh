#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: competing instances execute each scheduled job once under the distributed lock.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements
require_compose

service="${AUTHKIT_COMPOSE_SERVICE:-authkit}"
scale="${AUTHKIT_LOCK_CONTENTION_SCALE:-2}"
echo "Scaling ${service} to ${scale} instances temporarily to observe scheduler lock contention."
compose up -d --scale "${service}=${scale}"
sleep "${AUTHKIT_CHAOS_SECONDS:-60}"
compose up -d --scale "${service}=1"
echo "Scale restored to one. Inspect scheduler lock metrics and duplicate job evidence."
