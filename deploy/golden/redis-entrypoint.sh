#!/bin/sh
set -eu

password="$(sed -e '${s/[[:space:]]*$//;}' /run/secrets/redis_password)"
if [ -z "${password}" ]; then
  echo "Redis password secret is empty" >&2
  exit 1
fi

umask 0077
configuration=/data/authkit-redis-runtime.conf
{
  echo "appendonly yes"
  echo "appendfsync everysec"
  printf 'requirepass %s\n' "${password}"
} >"${configuration}"
unset password

exec redis-server "${configuration}"
