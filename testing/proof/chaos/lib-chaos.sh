#!/usr/bin/env bash

chaos_requirements() {
  if [[ "${AUTHKIT_CHAOS_APPROVED:-false}" != "true" ]]; then
    echo "FAIL: set AUTHKIT_CHAOS_APPROVED=true after confirming this is a local/HML proof window." >&2
    exit 1
  fi
  if [[ -z "${AUTHKIT_BASE_URL:-}" ]]; then
    echo "FAIL: AUTHKIT_BASE_URL is required." >&2
    exit 1
  fi
  case "${AUTHKIT_BASE_URL}" in
    *localhost*|*127.0.0.1*|*.local*|*.test*|*.internal*|*.hml*|*.staging*) ;;
    *)
      if [[ "${ALLOW_PRODUCTION_PROOF:-false}" != "true" ]]; then
        echo "FAIL: refusing production-looking AUTHKIT_BASE_URL for chaos." >&2
        exit 1
      fi
      ;;
  esac
}

require_compose() {
  if [[ -z "${COMPOSE_FILE:-}" ]]; then
    echo "FAIL: COMPOSE_FILE is required for this chaos script." >&2
    exit 1
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required for this chaos script." >&2
    exit 1
  fi
}

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}
