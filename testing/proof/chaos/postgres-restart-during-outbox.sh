#!/usr/bin/env bash
set -euo pipefail

# Expected behavior: outbox processing retries idempotently; SENT messages are not overwritten by stale failures.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testing/proof/chaos/lib-chaos.sh
source "${script_dir}/lib-chaos.sh"
chaos_requirements
require_compose

echo "Restarting PostgreSQL during outbox proof."
compose restart postgres
echo "PostgreSQL restart requested. Inspect scheduler failures, email retry/dead metrics, and outbox state."
