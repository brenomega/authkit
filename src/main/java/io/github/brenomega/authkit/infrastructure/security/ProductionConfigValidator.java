package io.github.brenomega.authkit.infrastructure.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxTiming;

/**
 * Validates production environment configurations to prevent deployment with 
 * default credentials or configuration vulnerabilities (DT 3.6.3).
 *
 * <p>Throws IllegalStateException immediately if insecure credentials, empty tokens,
 * or default placeholder settings are detected outside of test/dev profiles.</p>
 */
@Component
public class ProductionConfigValidator implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ProductionConfigValidator.class);

    private final Environment environment;

    public ProductionConfigValidator(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments args) {
        List<String> activeProfiles = Arrays.asList(environment.getActiveProfiles());

        // Skip validation for test or dev profiles or when running inside Spring Boot tests
        if (activeProfiles.contains("test") 
                || activeProfiles.contains("dev") 
                || environment.containsProperty("org.springframework.boot.test.context.SpringBootTestContextBootstrapper")) {
            log.info("Security configuration validation bypassed in test/dev environment.");
            return;
        }

        log.info("Running Production Configuration Security Checks...");

        validateCredential("spring.datasource.username", "postgres", "CHANGE-ME-DB-USER");
        validateCredential("spring.datasource.password", "secretpassword", "CHANGE-ME-DB-PASSWORD");
        validateCredential("spring.data.redis.password", "redis", "password", "CHANGE-ME-REDIS-PASSWORD");
        validateEmailDispatchMode();
        validateCredential("app.security.worker-token", "secure-production-worker-token", "mock-token", "CHANGE-ME-SECURE-WORKER-TOKEN");
        validateEmailProvider();
        validateCredential("authkit.auth.jwt.issuer", "authkit");
        validateCredential("authkit.auth.jwt.audience", "authkit-api");
        validateCredential("authkit.auth.jwt.key-id");
        validateOptionalJwtPublicKeyRotationList("authkit.auth.jwt.retiring-public-keys");
        validateOptionalKeyIdList("authkit.auth.jwt.revoked-key-ids");
        validateHttpsUrl("authkit.auth.frontend.activation-url", "https://authkit.io/activate");
        validateHttpsUrl("authkit.auth.frontend.password-reset-url", "https://frontend.url/reset-password");
        validateCredential("authkit.auth.compliance.terms-version");
        validateCredential("authkit.auth.compliance.privacy-policy-version");
        validateCredential("authkit.auth.compliance.lawful-basis");
        validateCredential("authkit.auth.audit.hash-pepper",
                "test-only-authkit-audit-hash-pepper-32-bytes",
                "local-development-audit-hash-pepper-change-for-prod",
                "CHANGE-ME-AUDIT-HASH-PEPPER-AT-LEAST-32-CHARS");
        validateCredential("authkit.auth.mfa.secret-encryption-key",
                "test-only-authkit-mfa-secret-key-32-bytes",
                "local-development-mfa-secret-key-change-for-prod",
                "CHANGE-ME-MFA-SECRET-ENCRYPTION-KEY-AT-LEAST-32-CHARS");
        validateCredential("authkit.auth.mfa.secret-encryption-key-id", "mfa-key-1", "test-mfa-key-1");
        validateOptionalKeyRotationList("authkit.auth.mfa.previous-secret-encryption-keys");
        validateMinLong("authkit.auth.mfa.secret-encryption-kdf-iterations", 100000);
        validateBoolean("authkit.auth.cookie.http-only", true);
        validateBoolean("authkit.auth.cookie.secure", true);
        validateBoolean("authkit.auth.csrf.enabled", true);
        validateBoolean("authkit.auth.cors.enabled", true);
        validateCorsOrigins();
        validateMaxLong("authkit.auth.abuse-control.capacity-multiplier", 1);
        validateCredential("authkit.auth.csrf.cookie-name");
        validateCredential("authkit.auth.csrf.header-name");
        validateBoolean("authkit.auth.registration.stealth-conflicts", true);
        validateBoolean("authkit.auth.passkey.allow-origin-port", false);
        validateMinLong("authkit.auth.email-provider.connect-timeout-ms", 100);
        validateMinLong("authkit.auth.email-provider.read-timeout-ms", 100);
        validateMinLong("authkit.auth.email-provider.max-attempts", 1);
        validateMinLong("security.argon2.memory", 19456);
        validateMinLong("security.argon2.iterations", 2);
        validateMinLong("security.argon2.parallelism", 1);

        log.info("Production configuration security checks PASSED successfully.");
    }

    private void validateCredential(@NonNull String propertyKey, String... illegalValues) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Required property '" + propertyKey + "' is missing or empty!");
        }

        if (value.startsWith("${") || value.startsWith("CHANGE-ME")) {
            log.error("CRITICAL SECURITY ERROR: Key '{}' has an unresolved placeholder value.", propertyKey);
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has an unresolved placeholder value. Startup aborted.");
        }

        for (String illegal : illegalValues) {
            if (value.equalsIgnoreCase(illegal)) {
                log.error("CRITICAL SECURITY ERROR: Key '{}' has an insecure default or placeholder value: '{}'", propertyKey, value);
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has a default or placeholder value. Startup aborted.");
            }
        }
    }

    private void validateBoolean(@NonNull String propertyKey, boolean requiredValue) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Required property '" + propertyKey + "' is missing or empty!");
        }

        boolean actual = Boolean.parseBoolean(value);
        if (actual != requiredValue) {
            log.error("CRITICAL SECURITY ERROR: Key '{}' must be set to '{}'.", propertyKey, requiredValue);
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has an insecure value. Startup aborted.");
        }
    }

    private void validateHttpsUrl(@NonNull String propertyKey, String... illegalValues) {
        validateCredential(propertyKey, illegalValues);
        String value = environment.getProperty(propertyKey);
        if (value == null || !value.startsWith("https://")) {
            log.error("CRITICAL SECURITY ERROR: Key '{}' must use HTTPS.", propertyKey);
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must use HTTPS. Startup aborted.");
        }
    }

    private void validateMinLong(@NonNull String propertyKey, long minimumValue) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Required property '" + propertyKey + "' is missing or empty!");
        }
        try {
            long actual = Long.parseLong(value);
            if (actual < minimumValue) {
                log.error("CRITICAL SECURITY ERROR: Key '{}' must be at least '{}'.", propertyKey, minimumValue);
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' is below the production minimum. Startup aborted.");
            }
        } catch (NumberFormatException ex) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must be numeric. Startup aborted.", ex);
        }
    }

    private void validateMaxLong(@NonNull String propertyKey, long maximumValue) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Required property '" + propertyKey + "' is missing or empty!");
        }
        try {
            long actual = Long.parseLong(value);
            if (actual > maximumValue) {
                log.error("CRITICAL SECURITY ERROR: Key '{}' must be at most '{}'.", propertyKey, maximumValue);
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' is above the production maximum. Startup aborted.");
            }
        } catch (NumberFormatException ex) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must be numeric. Startup aborted.", ex);
        }
    }

    private void validateEmailProvider() {
        String provider = environment.getProperty("authkit.auth.email-provider.type", "resend");
        if ("resend".equals(provider)) {
            validateCredential("resend.api.key", "mock-key", "test-resend-key", "CHANGE-ME-RESEND-API-KEY");
            return;
        }
        if ("logging".equals(provider)) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Logging email provider cannot be used in production. Startup aborted.");
        }
        throw new IllegalStateException("CRITICAL SECURITY ERROR: Unsupported email provider '" + provider + "'. Startup aborted.");
    }

    private void validateEmailDispatchMode() {
        String dispatchMode = environment.getProperty("authkit.auth.email-outbox.dispatch-mode", "queue");
        if ("queue".equals(dispatchMode)) {
            validateCredential("spring.rabbitmq.username", "guest", "CHANGE-ME-RABBIT-USER");
            validateCredential("spring.rabbitmq.password", "guest", "CHANGE-ME-RABBIT-PASSWORD");
            return;
        }
        if ("direct".equals(dispatchMode)) {
            if (preserveRabbitObservability()) {
                validateCredential("spring.rabbitmq.username", "guest", "CHANGE-ME-RABBIT-USER");
                validateCredential("spring.rabbitmq.password", "guest", "CHANGE-ME-RABBIT-PASSWORD");
            }
            validateDirectEmailDeliveryTimeout();
            return;
        }
        throw new IllegalStateException("CRITICAL SECURITY ERROR: Unsupported email outbox dispatch mode '" + dispatchMode + "'. Startup aborted.");
    }

    private boolean preserveRabbitObservability() {
        return Boolean.parseBoolean(environment.getProperty(
                "authkit.auth.email-outbox.preserve-rabbit-observability",
                "false"));
    }

    private void validateDirectEmailDeliveryTimeout() {
        AuthProperties timingProperties = directEmailTimingProperties();
        Duration deliveryAckTimeout = EmailOutboxTiming.deliveryAckTimeout(timingProperties);
        Duration providerBudget = EmailOutboxTiming.providerRetryBudget(timingProperties);
        Duration directProcessingLockTimeout = EmailOutboxTiming.directProcessingLockTimeout(timingProperties);
        Duration executorWaitTimeout = EmailOutboxTiming.directExecutorWaitTimeout(timingProperties);

        if (deliveryAckTimeout.compareTo(providerBudget) <= 0) {
            log.error(
                    "CRITICAL SECURITY ERROR: Direct email delivery timeout must exceed provider retry budget. timeoutMs={}, providerBudgetMs={}",
                    deliveryAckTimeout.toMillis(),
                    providerBudget.toMillis());
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Direct email delivery timeout is below the provider retry budget. Startup aborted.");
        }
        log.info(
                "Direct email timeout checks passed. deliveryAckTimeoutMs={}, providerBudgetMs={}, executorWaitBudgetMs={}, effectiveProcessingLockMs={}",
                deliveryAckTimeout.toMillis(),
                providerBudget.toMillis(),
                executorWaitTimeout.toMillis(),
                directProcessingLockTimeout.toMillis());
    }

    private AuthProperties directEmailTimingProperties() {
        AuthProperties properties = new AuthProperties();
        AuthProperties.EmailProvider provider = properties.getEmailProvider();
        AuthProperties.EmailOutbox outbox = properties.getEmailOutbox();

        provider.setMaxAttempts((int) getLongProperty("authkit.auth.email-provider.max-attempts", provider.getMaxAttempts()));
        provider.setConnectTimeoutMs((int) getLongProperty("authkit.auth.email-provider.connect-timeout-ms", provider.getConnectTimeoutMs()));
        provider.setReadTimeoutMs((int) getLongProperty("authkit.auth.email-provider.read-timeout-ms", provider.getReadTimeoutMs()));
        provider.setRetryBackoffMs(getLongProperty("authkit.auth.email-provider.retry-backoff-ms", provider.getRetryBackoffMs()));

        outbox.setDeliveryAckTimeoutSeconds(getLongProperty(
                "authkit.auth.email-outbox.delivery-ack-timeout-seconds",
                outbox.getDeliveryAckTimeoutSeconds()));
        outbox.setLockTtlSeconds(getLongProperty("authkit.auth.email-outbox.lock-ttl-seconds", outbox.getLockTtlSeconds()));
        outbox.setDirectCorePoolSize((int) getLongProperty(
                "authkit.auth.email-outbox.direct-core-pool-size",
                outbox.getDirectCorePoolSize()));
        outbox.setDirectQueueCapacity((int) getLongProperty(
                "authkit.auth.email-outbox.direct-queue-capacity",
                outbox.getDirectQueueCapacity()));
        return properties;
    }

    private long getLongProperty(@NonNull String propertyKey, long defaultValue) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ex) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must be numeric. Startup aborted.", ex);
        }
    }

    private void validateOptionalKeyRotationList(@NonNull String propertyKey) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            return;
        }
        if (value.startsWith("${") || value.contains("CHANGE-ME")) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has an unresolved placeholder value. Startup aborted.");
        }
        for (String entry : value.split(";")) {
            if (entry.isBlank()) {
                continue;
            }
            int separator = entry.indexOf('=');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must use keyId=secret entries separated by semicolons.");
            }
            String keyId = entry.substring(0, separator).trim();
            String keyMaterial = entry.substring(separator + 1).trim();
            if (!keyId.matches("[A-Za-z0-9._-]{1,64}") || keyMaterial.length() < 32) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' contains an invalid key id or short key material.");
            }
        }
    }

    private void validateOptionalJwtPublicKeyRotationList(@NonNull String propertyKey) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            return;
        }
        if (value.startsWith("${") || value.contains("CHANGE-ME")) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has an unresolved placeholder value. Startup aborted.");
        }
        for (String entry : value.split(";")) {
            if (entry.isBlank()) {
                continue;
            }
            int separator = entry.indexOf('=');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' must use keyId=publicKey entries separated by semicolons.");
            }
            String keyId = entry.substring(0, separator).trim();
            String keyMaterial = entry.substring(separator + 1).trim();
            if (!keyId.matches("[A-Za-z0-9._-]{1,64}") || keyMaterial.length() < 16) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' contains an invalid key id or missing public key material.");
            }
        }
    }

    private void validateOptionalKeyIdList(@NonNull String propertyKey) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            return;
        }
        if (value.startsWith("${") || value.contains("CHANGE-ME")) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' has an unresolved placeholder value. Startup aborted.");
        }
        for (String item : value.split("[,;]")) {
            String keyId = item.trim();
            if (!keyId.isBlank() && !keyId.matches("[A-Za-z0-9._-]{1,64}")) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Property '" + propertyKey + "' contains an invalid key id.");
            }
        }
    }

    private void validateCorsOrigins() {
        String origins = environment.getProperty("authkit.auth.cors.allowed-origins");
        if (origins == null || origins.isBlank()) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: CORS allowed origins must be explicit in production.");
        }
        boolean credentials = Boolean.parseBoolean(environment.getProperty("authkit.auth.cors.allow-credentials", "true"));
        for (String origin : origins.split(",")) {
            String trimmed = origin.trim();
            if (trimmed.isBlank()) {
                continue;
            }
            if ("*".equals(trimmed) && credentials) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: CORS wildcard cannot be used with credentials.");
            }
            if (trimmed.startsWith("http://") && !trimmed.startsWith("http://localhost")) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: Production CORS origins must use HTTPS.");
            }
        }
    }
}
