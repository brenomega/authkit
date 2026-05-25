package io.github.brenomega.authkit.service;

import java.time.Duration;
import java.time.Instant;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Enforces configured data-retention windows for privacy governance.
 */
@Service
@ConditionalOnProperty(prefix = "authkit.auth.compliance", name = "retention-job-enabled", havingValue = "true", matchIfMissing = true)
public class DataRetentionService {

    private static final Logger log = LoggerFactory.getLogger(DataRetentionService.class);

    private final SecurityEventRepository securityEventRepository;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;

    public DataRetentionService(SecurityEventRepository securityEventRepository,
                                AuthProperties authProperties,
                                MeterRegistry meterRegistry) {
        this.securityEventRepository = securityEventRepository;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
    }

    @Transactional
    @Scheduled(cron = "${authkit.auth.compliance.retention-job-cron:0 30 3 * * *}")
    public void purgeExpiredSecurityEvents() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(authProperties.getCompliance().getSecurityEventRetentionDays()));
        long deleted = securityEventRepository.deleteByOccurredAtBefore(cutoff);
        if (deleted > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "security_events").increment(deleted);
            log.info("Purged {} security events older than configured retention cutoff.", deleted);
        }
    }
}
