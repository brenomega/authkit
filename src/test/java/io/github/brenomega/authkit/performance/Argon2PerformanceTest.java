package io.github.brenomega.authkit.performance;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Tag("performance")
class Argon2PerformanceTest {

    @Test
    void encodeAndVerifyStayWithinGenerousLocalProbeBudget() {
        PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 2, 32768, 2);

        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            String hash = encoder.encode("AuthKit performance probe password 32!");
            assertTrue(encoder.matches("AuthKit performance probe password 32!", hash));
        });
    }
}
