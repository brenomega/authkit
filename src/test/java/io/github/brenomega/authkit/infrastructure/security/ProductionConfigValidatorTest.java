package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProductionConfigValidatorTest {

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
    @DisplayName("Production validation allows direct email dispatch without RabbitMQ credentials")
    void run_directEmailDispatchWithoutRabbitCredentials_allowsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "direct");

        assertDoesNotThrow(() -> new ProductionConfigValidator(environment).run(null));
    }

    @Test
    @DisplayName("Production validation rejects unsupported email dispatch mode")
    void run_unsupportedEmailDispatchMode_rejectsStartup() {
        MockEnvironment environment = productionEnvironmentBase()
                .withProperty("authkit.auth.email-outbox.dispatch-mode", "unsupported");

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
        return new MockEnvironment()
                .withProperty("spring.datasource.username", "authkit")
                .withProperty("spring.datasource.password", "db-prod-secret")
                .withProperty("spring.data.redis.password", "redis-prod-secret")
                .withProperty("app.security.worker-token", "worker-prod-secret")
                .withProperty("resend.api.key", "re_prod_secret")
                .withProperty("authkit.auth.jwt.issuer", "https://auth.example.com")
                .withProperty("authkit.auth.jwt.audience", "https://api.example.com")
                .withProperty("authkit.auth.jwt.key-id", "authkit-prod-key-1")
                .withProperty("authkit.auth.jwt.retiring-public-keys", "")
                .withProperty("authkit.auth.jwt.revoked-key-ids", "")
                .withProperty("authkit.auth.frontend.activation-url", "https://app.example.com/activate")
                .withProperty("authkit.auth.frontend.password-reset-url", "https://app.example.com/reset-password")
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
                .withProperty("authkit.auth.passkey.allow-origin-port", "false")
                .withProperty("authkit.auth.email-provider.type", "resend")
                .withProperty("authkit.auth.email-provider.connect-timeout-ms", "2000")
                .withProperty("authkit.auth.email-provider.read-timeout-ms", "5000")
                .withProperty("authkit.auth.email-provider.max-attempts", "3")
                .withProperty("authkit.auth.email-provider.retry-backoff-ms", "250")
                .withProperty("authkit.auth.email-outbox.delivery-ack-timeout-seconds", "600")
                .withProperty("security.argon2.memory", "32768")
                .withProperty("security.argon2.iterations", "2")
                .withProperty("security.argon2.parallelism", "2");
    }
}
