package io.github.brenomega.authkit.infrastructure.scheduling;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables runtime maintenance scheduling by default.
 *
 * <p>The switch exists so test application contexts can exercise jobs explicitly
 * without background executions racing schema setup or teardown. Production
 * validation rejects disabling the scheduler.</p>
 */
@Configuration
@EnableScheduling
@ConditionalOnProperty(prefix = "authkit.auth.scheduler", name = "enabled",
        havingValue = "true", matchIfMissing = true)
public class SchedulingConfig {
}
