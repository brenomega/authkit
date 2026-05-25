package io.github.brenomega.authkit.infrastructure.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

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
        validateCredential("spring.rabbitmq.username", "guest", "CHANGE-ME-RABBIT-USER");
        validateCredential("spring.rabbitmq.password", "guest", "CHANGE-ME-RABBIT-PASSWORD");
        validateCredential("app.security.worker-token", "secure-production-worker-token", "mock-token", "CHANGE-ME-SECURE-WORKER-TOKEN");
        validateCredential("resend.api.key", "mock-key", "test-resend-key", "CHANGE-ME-RESEND-API-KEY");
        validateCredential("authkit.auth.jwt.issuer", "authkit");
        validateCredential("authkit.auth.jwt.audience", "authkit-api");
        validateCredential("authkit.auth.jwt.key-id");
        validateHttpsUrl("authkit.auth.frontend.activation-url", "https://authkit.io/activate");
        validateHttpsUrl("authkit.auth.frontend.password-reset-url", "https://frontend.url/reset-password");
        validateCredential("authkit.auth.compliance.terms-version");
        validateCredential("authkit.auth.compliance.privacy-policy-version");
        validateCredential("authkit.auth.compliance.lawful-basis");
        validateCredential("authkit.auth.audit.hash-pepper",
                "test-only-authkit-audit-hash-pepper-32-bytes",
                "local-development-audit-hash-pepper-change-for-prod",
                "CHANGE-ME-AUDIT-HASH-PEPPER-AT-LEAST-32-CHARS");
        validateBoolean("authkit.auth.cookie.http-only", true);
        validateBoolean("authkit.auth.cookie.secure", true);
        validateBoolean("authkit.auth.csrf.enabled", true);
        validateCredential("authkit.auth.csrf.cookie-name");
        validateCredential("authkit.auth.csrf.header-name");
        validateBoolean("authkit.auth.registration.stealth-conflicts", true);

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
}
