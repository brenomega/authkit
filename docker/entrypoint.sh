#!/bin/sh
set -eu

# Docker/Kubernetes secret-file bridge. Values are never printed.
for secret_name in \
  DB_PASSWORD REDIS_PASSWORD JWT_PUBLIC_KEY JWT_PRIVATE_KEY \
  AUTH_AUDIT_HASH_PEPPER AUTH_MFA_SECRET_ENCRYPTION_KEY WORKER_TOKEN \
  RESEND_API_KEY AUTH_EMAIL_SMTP_PASSWORD AUTH_RETENTION_DB_PASSWORD \
  SPRING_FLYWAY_PASSWORD
do
  eval "secret_value=\${${secret_name}:-}"
  eval "secret_file=\${${secret_name}_FILE:-}"
  if [ -n "${secret_value}" ] && [ -n "${secret_file}" ]; then
    echo "Both ${secret_name} and ${secret_name}_FILE are set" >&2
    exit 1
  fi
  if [ -n "${secret_file}" ]; then
    if [ ! -r "${secret_file}" ]; then
      echo "Secret file for ${secret_name} is not readable" >&2
      exit 1
    fi
    secret_value="$(sed -e '${s/[[:space:]]*$//;}' "${secret_file}")"
    if [ -z "${secret_value}" ]; then
      echo "Secret file for ${secret_name} is empty" >&2
      exit 1
    fi
    export "${secret_name}=${secret_value}"
  fi
done

if [ "${1:-}" = "bootstrap-admin" ]; then
  if [ "$#" -ne 1 ]; then
    echo "bootstrap-admin accepts its secret document only through stdin or AUTHKIT_BOOTSTRAP_INPUT_FILE" >&2
    exit 1
  fi
  exec java \
    -XX:+UseContainerSupport \
    -XX:MaxRAMPercentage=75.0 \
    -Djava.security.egd=file:/dev/./urandom \
    -jar /app/app.jar \
    --spring.main.web-application-type=none \
    --authkit.bootstrap.enabled=true
fi

exec "$@"
