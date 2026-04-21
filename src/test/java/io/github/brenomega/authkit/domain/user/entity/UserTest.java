package io.github.brenomega.authkit.domain.user.entity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the {@link User} entity's PII-safe {@code toString()}
 * implementation (DT 3.4.9).
 */
class UserTest {

    private static final String TEST_EMAIL = "user@example.com";
    private static final String TEST_PASSWORD_HASH =
            "$argon2id$v=19$m=65536,t=3,p=2$someSalt$someHash";

    @Test
    @DisplayName("toString() must NOT contain the password hash")
    void toStringExcludesPassword() {
        User user = new User(TEST_EMAIL, TEST_PASSWORD_HASH);

        String result = user.toString();

        assertFalse(result.contains(TEST_PASSWORD_HASH),
                "toString() must never expose the password hash");
        assertFalse(result.toLowerCase().contains("password"),
                "toString() must not even mention the 'password' field");
    }

    @Test
    @DisplayName("toString() must mask the email address")
    void toStringMasksEmail() {
        User user = new User(TEST_EMAIL, TEST_PASSWORD_HASH);

        String result = user.toString();

        assertFalse(result.contains(TEST_EMAIL),
                "toString() must not expose the full email");
        assertTrue(result.contains("u***@example.com"),
                "toString() should show a masked email like 'u***@example.com'");
    }

    @Test
    @DisplayName("toString() must include the user id and role")
    void toStringIncludesIdAndRole() {
        User user = new User(TEST_EMAIL, TEST_PASSWORD_HASH);

        String result = user.toString();

        assertTrue(result.contains("id="), "toString() should include the id field");
        assertTrue(result.contains("role=USER"), "toString() should include the role");
    }

    @Test
    @DisplayName("toString() handles null email gracefully")
    void toStringHandlesNullEmail() {
        User user = new User(null, TEST_PASSWORD_HASH);

        String result = user.toString();

        assertTrue(result.contains("[REDACTED]"),
                "null email should be shown as [REDACTED]");
    }
}
