package io.github.brenomega.authkit.infrastructure.aop;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link LoggingAspect} PII sanitization logic (DT 3.4.1).
 *
 * <p>These tests verify that sensitive parameter names are correctly
 * identified and masked before any value can reach log output.</p>
 */
class LoggingAspectTest {

    // -------------------------------------------------------------------------
    // Sensitivity detection
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("'password' is detected as sensitive")
    void passwordIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("password"));
    }

    @Test
    @DisplayName("'token' is detected as sensitive")
    void tokenIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("token"));
    }

    @Test
    @DisplayName("'secret' is detected as sensitive")
    void secretIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("secret"));
    }

    @Test
    @DisplayName("'jwt' is detected as sensitive")
    void jwtIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("jwt"));
    }

    @Test
    @DisplayName("'refreshToken' is detected as sensitive (case-insensitive)")
    void refreshTokenIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("refreshToken"));
    }

    @Test
    @DisplayName("'Authorization' is detected as sensitive (case-insensitive)")
    void authorizationIsSensitive() {
        assertTrue(LoggingAspect.isSensitive("Authorization"));
    }

    // -------------------------------------------------------------------------
    // Non-sensitive parameters
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("'email' is not redacted by keyword because it is masked separately")
    void emailIsNotSensitive() {
        assertFalse(LoggingAspect.isSensitive("email"));
    }

    @Test
    @DisplayName("'username' is NOT sensitive — allowed in logs")
    void usernameIsNotSensitive() {
        assertFalse(LoggingAspect.isSensitive("username"));
    }

    @Test
    @DisplayName("'id' is NOT sensitive — allowed in logs")
    void idIsNotSensitive() {
        assertFalse(LoggingAspect.isSensitive("id"));
    }
}
