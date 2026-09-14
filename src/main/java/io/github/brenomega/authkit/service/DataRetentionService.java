package io.github.brenomega.authkit.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.Objects;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.persistence.RetentionDeleteGateway;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.PasskeyChallengeRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.SocialLoginTransactionRepository;
import io.github.brenomega.authkit.repository.OAuthAuthorizationTransactionRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenFamilyRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenRepository;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshTokenFamily;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/**
 * Applies configured retention limits to audit, credential, protocol, and deleted-account data.
 *
 * <p>A distributed scheduler lock prevents overlapping workers. Purges use bounded
 * batches and independent {@code REQUIRES_NEW} transactions so one committed batch
 * is not rolled back when a later batch fails. Deleted-account removal follows the
 * repository dependency order required by foreign keys; the job exposes counts and
 * failures through metrics without weakening persistence errors.</p>
 */
@Service
@ConditionalOnProperty(
    prefix = "authkit.auth.compliance",
    name = "retention-job-enabled",
    havingValue = "true",
    matchIfMissing = true)
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
    private final EmailOutboxService emailOutboxService;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;
    private final TransactionTemplate transactionTemplate;
    private final RetentionDeleteGateway retentionDeleteGateway;
    private final SocialIdentityRepository socialIdentityRepository;
    private final SocialLoginTransactionRepository socialLoginTransactionRepository;
    private final OAuthAuthorizationTransactionRepository oauthAuthorizationTransactionRepository;
    private final OAuthRefreshTokenFamilyRepository oauthRefreshTokenFamilyRepository;
    private final OAuthRefreshTokenRepository oauthRefreshTokenRepository;
    private final io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectRepository securityEffects;

    public DataRetentionService(SecurityEventRepository securityEventRepository,
                                UserRepository userRepository,
                                PasskeyChallengeRepository passkeyChallengeRepository,
                                OAuthAuthorizationCodeRepository oauthAuthorizationCodeRepository,
                                MfaTotpCredentialRepository mfaTotpCredentialRepository,
                                MfaBackupCodeRepository mfaBackupCodeRepository,
                                PasskeyCredentialRepository passkeyCredentialRepository,
                                OAuthConsentRepository oauthConsentRepository,
                                PasswordHistoryRepository passwordHistoryRepository,
                                EmailOutboxService emailOutboxService,
                                AuthProperties authProperties,
                                MeterRegistry meterRegistry,
                                TransactionTemplate transactionTemplate,
                                RetentionDeleteGateway retentionDeleteGateway,
                                SocialIdentityRepository socialIdentityRepository,
                                SocialLoginTransactionRepository socialLoginTransactionRepository,
                                OAuthAuthorizationTransactionRepository oauthAuthorizationTransactionRepository,
                                OAuthRefreshTokenFamilyRepository oauthRefreshTokenFamilyRepository,
                                OAuthRefreshTokenRepository oauthRefreshTokenRepository,
                                io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectRepository securityEffects) {
        this.securityEventRepository = securityEventRepository;
        this.userRepository = userRepository;
        this.passkeyChallengeRepository = passkeyChallengeRepository;
        this.oauthAuthorizationCodeRepository = oauthAuthorizationCodeRepository;
        this.mfaTotpCredentialRepository = mfaTotpCredentialRepository;
        this.mfaBackupCodeRepository = mfaBackupCodeRepository;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.oauthConsentRepository = oauthConsentRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.emailOutboxService = emailOutboxService;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
        this.transactionTemplate = transactionTemplate;
        this.retentionDeleteGateway = retentionDeleteGateway;
        this.socialIdentityRepository = socialIdentityRepository;
        this.socialLoginTransactionRepository = socialLoginTransactionRepository;
        this.oauthAuthorizationTransactionRepository = oauthAuthorizationTransactionRepository;
        this.oauthRefreshTokenFamilyRepository = oauthRefreshTokenFamilyRepository;
        this.oauthRefreshTokenRepository = oauthRefreshTokenRepository;
        this.securityEffects = securityEffects;
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Removes records older than their configured cutoffs under the cluster-wide retention lock.
     *
     * @throws RuntimeException if any purge fails; already committed batches remain committed
     */
    @Scheduled(cron = "${authkit.auth.compliance.retention-job-cron:0 30 3 * * *}")
    @SchedulerLock(name = "dataRetention",
            lockAtMostFor = "${authkit.auth.scheduler.retention-lock-at-most:PT2H}",
            lockAtLeastFor = "${authkit.auth.scheduler.retention-lock-at-least:PT1M}")
    public void purgeExpiredSecurityEvents() {
        try {
            purgeExpiredSecurityEventsInternal();
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.scheduler.failure", "job", "data_retention").increment();
            throw ex;
        }
    }

    private void purgeExpiredSecurityEventsInternal() {
        Instant now = Instant.now();
        int batchSize = authProperties.getCompliance().getRetentionBatchSize();
        Instant completedCutoff = now.minus(Duration.ofDays(
                authProperties.getCompliance().getSecurityEventRetentionDays()));
        int purged;
        do {
            purged = transactionTemplate.execute(status -> securityEffects.purgeCompletedBatch(completedCutoff, batchSize));
            meterRegistry.counter("security.retention.deleted", "dataset", "security_effect_outbox").increment(purged);
        } while (purged == batchSize);
        do {
            purged = transactionTemplate.execute(status -> securityEffects.purgeExpiredActivationsBatch(now, batchSize));
        } while (purged == batchSize);
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
        int deletedPasskeyChallenges = transactionTemplate.execute(
                status -> passkeyChallengeRepository.deleteExpired(now));
        if (deletedPasskeyChallenges > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "passkey_challenges")
                    .increment(deletedPasskeyChallenges);
        }

        @SuppressWarnings("null")
        int deletedAuthorizationCodes = transactionTemplate.execute(
                status -> oauthAuthorizationCodeRepository.deleteExpired(now));
        if (deletedAuthorizationCodes > 0) {
            meterRegistry.counter("security.retention.deleted", "dataset", "oauth_authorization_codes")
                    .increment(deletedAuthorizationCodes);
        }
        transactionTemplate.executeWithoutResult(status -> {
            oauthAuthorizationTransactionRepository.deleteExpired(now);
            oauthRefreshTokenRepository.deleteExpired(now);
        });
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
        return retentionDeleteGateway.purgeSecurityEvents(ids);
    }

    private long purgeUserIds(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return 0;
        }
        List<String> emails = userRepository.findAllById(ids).stream()
                .map(user -> user.getEmail())
                .filter(Objects::nonNull)
                .toList();
        passkeyChallengeRepository.deleteByUserIdIn(ids);
        socialLoginTransactionRepository.deleteByUserIdIn(ids);
        socialIdentityRepository.deleteByUserIdIn(ids);
        @SuppressWarnings("null")
        List<UUID> oauthRefreshFamilyIds = oauthRefreshTokenFamilyRepository.findByUserIdIn(ids).stream()
                .map(OAuthRefreshTokenFamily::getId)
                .toList();
        if (!oauthRefreshFamilyIds.isEmpty()) {
            oauthRefreshTokenRepository.deleteByFamilyIdIn(oauthRefreshFamilyIds);
        }
        oauthRefreshTokenFamilyRepository.deleteByUserIdIn(ids);
        oauthAuthorizationCodeRepository.deleteByUserIdIn(ids);
        oauthConsentRepository.deleteByUserIdIn(ids);
        passkeyCredentialRepository.deleteByUserIdIn(ids);
        mfaBackupCodeRepository.deleteByUserIdIn(ids);
        mfaTotpCredentialRepository.deleteByUserIdIn(ids);
        ids.forEach(passwordHistoryRepository::deleteByUserId);
        retentionDeleteGateway.purgeSecurityEventsForUsers(ids);
        retentionDeleteGateway.purgeConsentEventsForUsers(ids);
        emailOutboxService.deleteByRecipients(emails);
        return userRepository.purgeDeletedByIdIn(ids);
    }

    private record BatchPurgeResult(int selected, long deleted) {
    }
}
