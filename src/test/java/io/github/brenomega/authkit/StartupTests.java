package io.github.brenomega.authkit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test that verifies the Spring application context loads
 * successfully under the {@code test} profile.
 *
 * <p>Uses H2 in-memory database and disabled external dependencies
 * (Redis, RabbitMQ) as configured in {@code application-test.yml}
 * (DT 3.1.24).</p>
 */
@SpringBootTest
@ActiveProfiles("test")
class StartupTests {

	/**
	 * Validates that the application context bootstraps without errors.
	 */
	@Test
	void contextLoads() {
	}

}
