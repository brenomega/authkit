package io.github.brenomega.authkit.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.PasskeyChallengeRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;
import io.github.brenomega.authkit.repository.UserRepository;

/**
 * Enforces configured data-retention windows for privacy governance.
 */
@Service
@ConditionalOnProperty(prefix = "authkit.auth.compliance", name = "retention-job-enabled", havingValue = "true", matchIfMissing = true)
public class DataRetentionService {

    private static final Logger log = LoggerFactory.getLogger(DataRetentionService.class);

    private final SecurityEventRepository securityEventRepository;
    private final UserRepository userRepository;
    private final PasskeyChallengeRepository passkeyChallengeRepository;
    private final OAuthAuthorizationCodeRepository oauthAuthorizationCodeRepository;
    private final MfaTotpCredentialRepository mfaTotpCredentialRepository;
    private final MfaBackupCodeRepository mfaBackupCodeRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final OAuthConsentRepository oauthConsentRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final ConsentEventRepository consentEventRepository;
    private final EmailOutboxService emailOutboxService;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;
    private final TransactionTemplate transactionTemplate;

    public DataRetentionService(SecurityEventRepository securityEventRepository,
                                UserRepository userRepository,
                                PasskeyChallengeRepository passkeyChallengeRepository,
                                OAuthAuthorizationCodeRepository oauthAuthorizationCodeRepository,
                                MfaTotpCredentialRepository mfaTotpCredentialRepository,
                                MfaBackupCodeRepository mfaBackupCodeRepository,
                                PasskeyCredentialRepository passkeyCredentialRepository,
                                OAuthConsentRepository oauthConsentRepository,
                                PasswordHistoryRepository passwordHistoryRepository,
                                ConsentEventRepository consentEventRepository,
                                EmailOutboxService emailOutboxService,
                                AuthProperties authProperties,
                                MeterRegistry meterRegistry,
                                TransactionTemplate transactionTemplate) {
        this.securityEventRepository = securityEventRepository;
        this.userRepository = userRepository;
        this.passkeyChallengeRepository = passkeyChallengeRepository;
        this.oauthAuthorizationCodeRepository = oauthAuthorizationCodeRepository;
        this.mfaTotpCredentialRepository = mfaTotpCredentialRepository;
        this.mfaBackupCodeRepository = mfaBackupCodeRepository;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.oauthConsentRepository = oauthConsentRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.consentEventRepository = consentEventRepository;
        this.emailOutboxService = emailOutboxService;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
        this.transactionTemplate = transactionTemplate;
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Scheduled(cron = "${authkit.auth.compliance.retention-job-cron:0 30 3 * * *}")
    public void purgeExpiredSecurityEvents() {
        Instant now = Instant.now();
        int batchSize = authProperties.getCompliance().getRetentionBatchSize();
        long deletedEvents = purgeSecurityEventsInBatches(
                now.minus(Duration.ofDays(authProperties.getCompliance().getSecurityEventRetentionDays())),
                batchSize);
        if (deletedEvents > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "security_events").increment(deletedEvents);
            log.info("Purged {} security events older than configured retention cutoff.", deletedEvents);
        }

        long deletedAccounts = purgeDeletedUsersInBatches(
                now.minus(Duration.ofDays(authProperties.getCompliance().getDeletedAccountRetentionDays())),
                batchSize);
        if (deletedAccounts > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "deleted_users").increment(deletedAccounts);
            log.info("Purged {} anonymized deleted accounts older than configured retention cutoff.", deletedAccounts);
        }

        @SuppressWarnings("null")
        int deletedPasskeyChallenges = transactionTemplate.execute(status -> passkeyChallengeRepository.deleteExpired(now));
        if (deletedPasskeyChallenges > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "passkey_challenges")
                    .increment(deletedPasskeyChallenges);
        }

        @SuppressWarnings("null")
        int deletedAuthorizationCodes = transactionTemplate.execute(status -> oauthAuthorizationCodeRepository.deleteExpired(now));
        if (deletedAuthorizationCodes > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "oauth_authorization_codes")
                    .increment(deletedAuthorizationCodes);
        }
    }

    private long purgeSecurityEventsInBatches(Instant cutoff, int batchSize) {
        long totalDeleted = 0;
        BatchPurgeResult result;
        do {
            result = purgeSecurityEventBatch(cutoff, batchSize);
            totalDeleted += result.deleted();
            if (result.deleted() == 0) {
                break;
            }
        } while (result.selected() == batchSize);
        return totalDeleted;
    }

    private long purgeDeletedUsersInBatches(Instant cutoff, int batchSize) {
        long totalDeleted = 0;
        BatchPurgeResult result;
        do {
            result = purgeDeletedUserBatch(cutoff, batchSize);
            totalDeleted += result.deleted();
            if (result.deleted() == 0) {
                break;
            }
        } while (result.selected() == batchSize);
        return totalDeleted;
    }

    private BatchPurgeResult purgeSecurityEventBatch(Instant cutoff, int batchSize) {
        return transactionTemplate.execute(status -> {
            List<UUID> ids = securityEventRepository.findExpiredIds(cutoff, PageRequest.of(0, batchSize));
            long deleted = purgeSecurityEventIds(ids);
            return new BatchPurgeResult(ids.size(), deleted);
        });
    }

    private BatchPurgeResult purgeDeletedUserBatch(Instant cutoff, int batchSize) {
        return transactionTemplate.execute(status -> {
            List<UUID> ids = userRepository.findDeletedIdsBefore(cutoff, PageRequest.of(0, batchSize));
            long deleted = purgeUserIds(ids);
            return new BatchPurgeResult(ids.size(), deleted);
        });
    }

    private long purgeSecurityEventIds(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return 0;
        }
        return securityEventRepository.purgeByIdIn(ids);
    }

    private long purgeUserIds(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return 0;
        }
        List<String> emails = userRepository.findAllById(ids).stream()
                .map(user -> user.getEmail())
                .filter(java.util.Objects::nonNull)
                .toList();
        passkeyChallengeRepository.deleteByUserIdIn(ids);
        oauthAuthorizationCodeRepository.deleteByUserIdIn(ids);
        oauthConsentRepository.deleteByUserIdIn(ids);
        passkeyCredentialRepository.deleteByUserIdIn(ids);
        mfaBackupCodeRepository.deleteByUserIdIn(ids);
        mfaTotpCredentialRepository.deleteByUserIdIn(ids);
        ids.forEach(passwordHistoryRepository::deleteByUserId);
        securityEventRepository.purgeByUserReferences(ids);
        consentEventRepository.deleteByUserIdIn(ids);
        emailOutboxService.deleteByRecipients(emails);
        return userRepository.purgeDeletedByIdIn(ids);
    }

    private record BatchPurgeResult(int selected, long deleted) {
    }
}
