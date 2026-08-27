package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionConfigValidatorTest {

    @Test
    @DisplayName("Production validation rejects an omitted registration mode")
    void run_registrationModeOmitted_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.registration.mode", "");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects non-stealth registration conflicts")
    void run_registrationStealthConflictsDisabled_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.registration.stealth-conflicts", "false");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects HTTP frontend flow URLs")
    void run_httpFrontendUrl_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.frontend.password-reset-url", "http://app.example.com/reset-password");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects an HTTP email-change action URL")
    void run_httpEmailChangeUrl_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.frontend.email-change-url", "http://app.example.com/change-email");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects an HTTP OAuth authorization UI")
    void run_httpAuthorizationUi_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.oauth.authorization-ui-url", "http://app.example.com/oauth/authorize");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects relaxed abuse-control capacities")
    void run_abuseCapacityMultiplierRelaxed_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.abuse-control.capacity-multiplier", "1000");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects logging email provider")
    void run_loggingEmailProvider_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.email-provider.type", "logging");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation allows SMTP provider with TLS and required credentials")
    void run_smtpEmailProviderWithTlsAndCredentials_allowsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.email-provider.type", "smtp")
                .withProperty("authkit.auth.email-provider.smtp.host", "smtp.example.com")
                .withProperty("authkit.auth.email-provider.smtp.port", "587")
                .withProperty("authkit.auth.email-provider.smtp.auth", "true")
                .withProperty("authkit.auth.email-provider.smtp.username", "authkit@example.com")
                .withProperty("authkit.auth.email-provider.smtp.password", "smtp-prod-secret")
                .withProperty("authkit.auth.email-provider.smtp.start-tls-enabled", "true")
                .withProperty("authkit.auth.email-provider.smtp.start-tls-required", "true")
                .withProperty("authkit.auth.email-provider.smtp.ssl-enabled", "false");

        assertDoesNotThrow(() -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects SMTP provider without encrypted transport")
    void run_smtpEmailProviderWithoutTls_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.email-provider.type", "smtp")
                .withProperty("authkit.auth.email-provider.smtp.host", "smtp.example.com")
                .withProperty("authkit.auth.email-provider.smtp.port", "25")
                .withProperty("authkit.auth.email-provider.smtp.auth", "true")
                .withProperty("authkit.auth.email-provider.smtp.username", "authkit@example.com")
                .withProperty("authkit.auth.email-provider.smtp.password", "smtp-prod-secret")
                .withProperty("authkit.auth.email-provider.smtp.start-tls-enabled", "false")
                .withProperty("authkit.auth.email-provider.smtp.ssl-enabled", "false");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation allows direct email dispatch without RabbitMQ credentials")
    void run_directEmailDispatchWithoutRabbitCredentials_allowsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct");

        assertDoesNotThrow(() -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation allows explicit single-instance JDBC token storage")
    void run_jdbcTokenStorageSingleInstance_allowsStartupWithoutRedisPassword() {
        MockEnvironment environment = productionEnvironmentBaseWithoutRedis()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.token-storage.backend", "jdbc")
                .withProperty("authkit.auth.token-storage.single-instance-mode", "true")
                .withProperty("authkit.auth.abuse-control.fail-closed-high-risk", "false");

        assertDoesNotThrow(() -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects accidental JDBC token storage without single-instance flag")
    void run_jdbcTokenStorageWithoutSingleInstanceFlag_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBaseWithoutRedis()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.token-storage.backend", "jdbc")
                .withProperty("authkit.auth.token-storage.single-instance-mode", "false");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects unsupported email dispatch mode")
    void run_unsupportedEmailDispatchMode_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "unsupported");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation requires distributed scheduler locks when jobs are enabled")
    void run_scheduledJobsWithoutDistributedLock_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.scheduler.distributed-lock-enabled", "false")
                .withProperty("authkit.auth.email-outbox.enabled", "true");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects scheduler lock windows above safety bounds")
    void run_oversizedSchedulerLock_rejectsStartup() {
        MockEnvironment environment = productionEnvironment()
                .withProperty("authkit.auth.scheduler.email-poll-lock-at-most", "PT11M");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation requires Rabbit credentials when direct mode preserves Rabbit observability")
    void run_directEmailDispatchPreservingRabbitObservabilityWithoutRabbitCredentials_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.email-outbox.preserve-rabbit-observability", "true");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects direct email timeout below provider retry budget")
    void run_directEmailDeliveryTimeoutBelowProviderBudget_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct")
                .withProperty("authkit.auth.email-outbox.delivery-ack-timeout-seconds", "10");

        assertThrows(IllegalStateException.class, () -> new ProductionConfigValidator(environment).run(null));
    }

    private MockEnvironment productionEnvironment() {
        return productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "queue")
                .withProperty("spring.rabbitmq.username", "authkit")
                .withProperty("spring.rabbitmq.password", "rabbit-prod-secret");
    }

    private MockEnvironment productionEnvironmentBase() {
        return productionEnvironmentBaseWithoutRedis()
                .withProperty("spring.data.redis.password", "redis-prod-secret")
                .withProperty("authkit.auth.token-storage.backend", "redis")
                .withProperty("authkit.auth.token-storage.single-instance-mode", "false");
    }

    private MockEnvironment productionEnvironmentBaseWithoutRedis() {
        return new MockEnvironment()
                .withProperty("spring.datasource.username", "authkit")
                .withProperty("spring.datasource.password", "db-prod-secret")
                .withProperty("app.security.worker-token", "worker-prod-secret")
                .withProperty("resend.api.key", "re_prod_secret")
                .withProperty("authkit.auth.jwt.issuer", "https://auth.example.com")
                .withProperty("authkit.auth.jwt.audience", "https://api.example.com")
                .withProperty("authkit.auth.jwt.key-id", "authkit-prod-key-1")
                .withProperty("authkit.auth.jwt.retiring-public-keys", "")
                .withProperty("authkit.auth.jwt.revoked-key-ids", "")
                .withProperty("authkit.auth.frontend.activation-url", "https://app.example.com/activate")
                .withProperty("authkit.auth.frontend.password-reset-url", "https://app.example.com/reset-password")
                .withProperty("authkit.auth.frontend.email-change-url", "https://app.example.com/change-email")
                .withProperty("authkit.auth.oauth.authorization-ui-url", "https://app.example.com/oauth/authorize")
                .withProperty("authkit.auth.compliance.terms-version", "terms-2026")
                .withProperty("authkit.auth.compliance.privacy-policy-version", "privacy-2026")
                .withProperty("authkit.auth.compliance.lawful-basis", "consent")
                .withProperty("authkit.auth.audit.hash-pepper", "production-audit-hash-pepper-at-least-32-chars")
                .withProperty("authkit.auth.mfa.secret-encryption-key", "production-mfa-secret-key-at-least-32-chars")
                .withProperty("authkit.auth.mfa.secret-encryption-key-id", "prod-mfa-key-2026-05")
                .withProperty("authkit.auth.mfa.previous-secret-encryption-keys", "")
                .withProperty("authkit.auth.mfa.secret-encryption-kdf-iterations", "210000")
                .withProperty("authkit.auth.cookie.http-only", "true")
                .withProperty("authkit.auth.cookie.secure", "true")
                .withProperty("authkit.auth.csrf.enabled", "true")
                .withProperty("authkit.auth.cors.enabled", "true")
                .withProperty("authkit.auth.cors.allowed-origins", "https://app.example.com")
                .withProperty("authkit.auth.cors.allow-credentials", "true")
                .withProperty("authkit.auth.abuse-control.capacity-multiplier", "1")
                .withProperty("authkit.auth.csrf.cookie-name", "XSRF-TOKEN")
                .withProperty("authkit.auth.csrf.header-name", "X-XSRF-TOKEN")
                .withProperty("authkit.auth.registration.stealth-conflicts", "true")
                .withProperty("authkit.auth.registration.mode", "public")
                .withProperty("authkit.auth.passkey.allow-origin-port", "false")
                .withProperty("authkit.auth.email-provider.type", "resend")
                .withProperty("authkit.auth.email-provider.from", "AuthKit <auth@example.com>")
                .withProperty("authkit.auth.email-provider.connect-timeout-ms", "2000")
                .withProperty("authkit.auth.email-provider.read-timeout-ms", "5000")
                .withProperty("authkit.auth.email-provider.max-attempts", "3")
                .withProperty("authkit.auth.email-provider.retry-backoff-ms", "250")
                .withProperty("authkit.auth.email-templates.directory", "/run/config/email-templates")
                .withProperty("authkit.auth.token.access-token-ttl-seconds", "300")
                .withProperty("authkit.auth.password.hibp-enabled", "true")
                .withProperty("authkit.auth.abuse-control.fail-closed-high-risk", "true")
                .withProperty("authkit.auth.token-storage.jdbc.cleanup-delay-ms", "300000")
                .withProperty("authkit.auth.token-storage.jdbc.session-cursor-ttl-seconds", "300")
                .withProperty("authkit.auth.email-outbox.delivery-ack-timeout-seconds", "600")
                .withProperty("security.argon2.memory", "32768")
                .withProperty("security.argon2.iterations", "2")
                .withProperty("security.argon2.parallelism", "2");
    }
}
