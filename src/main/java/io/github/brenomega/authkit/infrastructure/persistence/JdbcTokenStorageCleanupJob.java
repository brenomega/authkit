package io.github.brenomega.authkit.infrastructure.persistence;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/** Runs maintenance for expired JDBC token state under a scheduler lock. */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend", havingValue = "jdbc")
public class JdbcTokenStorageCleanupJob {

    private final JdbcTokenStorage tokenStorage;
    private final MeterRegistry meterRegistry;

    public JdbcTokenStorageCleanupJob(JdbcTokenStorage tokenStorage,
                                      MeterRegistry meterRegistry) {
        this.tokenStorage = tokenStorage;
        this.meterRegistry = meterRegistry;
    }

    /** Deletes expired state and surfaces scheduler failure through metrics and the scheduler. */
    @Scheduled(fixedDelayString = "${authkit.auth.token-storage.jdbc.cleanup-delay-ms:300000}")
    @SchedulerLock(name = "jdbcTokenStorageCleanup",
            lockAtMostFor = "${authkit.auth.token-storage.jdbc.cleanup-lock-at-most:PT5M}")
    public void cleanupExpiredTokenState() {
        try {
            int deleted = tokenStorage.deleteExpired();
            meterRegistry.counter("security.token_storage.jdbc.cleanup", "outcome", "success").increment();
            if (deleted > 0) {
                meterRegistry.counter("security.token_storage.jdbc.cleanup.deleted").increment(deleted);
            }
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.scheduler.failure", "job", "jdbc_token_storage_cleanup").increment();
            throw ex;
        }
    }
}
