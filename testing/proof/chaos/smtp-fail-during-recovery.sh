#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: recovery request remains opaque; email outbox retries then respects terminal dead-state limits.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements
require_compose

service="${AUTHKIT_SMTP_COMPOSE_SERVICE:-mailpit}"
echo "Stopping SMTP service ${service} for ${AUTHKIT_CHAOS_SECONDS:-30}s during recovery proof."
compose stop "${service}"
sleep "${AUTHKIT_CHAOS_SECONDS:-30}"
compose start "${service}"
echo "SMTP service restarted. Inspect email retry/dead metrics and outbox backlog age."
