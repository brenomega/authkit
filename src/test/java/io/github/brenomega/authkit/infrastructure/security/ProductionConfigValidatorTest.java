package io.github.brenomega.authkit.infrastructure.security;

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

    private MockEnvironment productionEnvironment() {
        return new MockEnvironment()
                .withProperty("spring.datasource.username", "authkit")
                .withProperty("spring.datasource.password", "db-prod-secret")
                .withProperty("spring.rabbitmq.username", "authkit")
                .withProperty("spring.rabbitmq.password", "rabbit-prod-secret")
                .withProperty("app.security.worker-token", "worker-prod-secret")
                .withProperty("resend.api.key", "re_prod_secret")
                .withProperty("authkit.auth.jwt.issuer", "https://auth.example.com")
                .withProperty("authkit.auth.jwt.audience", "https://api.example.com")
                .withProperty("authkit.auth.jwt.key-id", "authkit-prod-key-1")
                .withProperty("authkit.auth.frontend.activation-url", "https://app.example.com/activate")
                .withProperty("authkit.auth.frontend.password-reset-url", "https://app.example.com/reset-password")
                .withProperty("authkit.auth.compliance.terms-version", "terms-2026")
                .withProperty("authkit.auth.compliance.privacy-policy-version", "privacy-2026")
                .withProperty("authkit.auth.compliance.lawful-basis", "consent")
                .withProperty("authkit.auth.audit.hash-pepper", "production-audit-hash-pepper-at-least-32-chars")
                .withProperty("authkit.auth.cookie.http-only", "true")
                .withProperty("authkit.auth.cookie.secure", "true")
                .withProperty("authkit.auth.csrf.enabled", "true")
                .withProperty("authkit.auth.csrf.cookie-name", "XSRF-TOKEN")
                .withProperty("authkit.auth.csrf.header-name", "X-XSRF-TOKEN")
                .withProperty("authkit.auth.registration.stealth-conflicts", "true");
    }
}
