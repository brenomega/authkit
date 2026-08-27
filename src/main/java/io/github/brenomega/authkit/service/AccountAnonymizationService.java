package io.github.brenomega.authkit.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.SocialLoginTransactionRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenFamilyRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.micrometer.core.instrument.MeterRegistry;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Irreversibly anonymizes accounts whose configured deletion grace has expired. */
@Service
@ConditionalOnProperty(prefix = "authkit.auth.compliance", name = "retention-job-enabled",
        havingValue = "true", matchIfMissing = true)
public class AccountAnonymizationService {

    private final UserRepository userRepository;
    private final SecurityEventService securityEventService;
    private final EmailOutboxService emailOutboxService;
    private final TokenStorage tokenStorage;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;
    private final TransactionTemplate transactionTemplate;
    private final SocialIdentityRepository socialIdentityRepository;
    private final SocialLoginTransactionRepository socialLoginTransactionRepository;
    private final OAuthRefreshTokenFamilyRepository oauthRefreshTokenFamilyRepository;
    private final OAuthRefreshTokenRepository oauthRefreshTokenRepository;

    public AccountAnonymizationService(UserRepository userRepository,
                                       SecurityEventService securityEventService,
                                       EmailOutboxService emailOutboxService,
                                       TokenStorage tokenStorage,
                                       UserAuthoritiesFilter userAuthoritiesFilter,
                                       AuthProperties authProperties,
                                       MeterRegistry meterRegistry,
                                       TransactionTemplate transactionTemplate,
                                       SocialIdentityRepository socialIdentityRepository,
                                       SocialLoginTransactionRepository socialLoginTransactionRepository,
                                       OAuthRefreshTokenFamilyRepository oauthRefreshTokenFamilyRepository,
                                       OAuthRefreshTokenRepository oauthRefreshTokenRepository) {
        this.userRepository = userRepository;
        this.securityEventService = securityEventService;
        this.emailOutboxService = emailOutboxService;
        this.tokenStorage = tokenStorage;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
        this.transactionTemplate = transactionTemplate;
        this.socialIdentityRepository = socialIdentityRepository;
        this.socialLoginTransactionRepository = socialLoginTransactionRepository;
        this.oauthRefreshTokenFamilyRepository = oauthRefreshTokenFamilyRepository;
        this.oauthRefreshTokenRepository = oauthRefreshTokenRepository;
        this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Scheduled(cron = "${authkit.auth.compliance.retention-job-cron:0 30 3 * * *}")
    @SchedulerLock(name = "accountAnonymization",
            lockAtMostFor = "${authkit.auth.scheduler.retention-lock-at-most:PT2H}",
            lockAtLeastFor = "${authkit.auth.scheduler.retention-lock-at-least:PT1M}")
    public void anonymizeExpiredDeletionRequests() {
        try {
            int batchSize = authProperties.getCompliance().getRetentionBatchSize();
            Instant cutoff = Instant.now().minus(Duration.ofDays(
                    authProperties.getCompliance().getDeletionGracePeriodDays()));
            int anonymized = 0;
            List<UUID> ids;
            do {
                ids = userRepository.findDeletionPendingIdsBefore(
                        AccountState.DELETION_PENDING, cutoff, PageRequest.of(0, batchSize));
                for (UUID id : ids) {
                    Boolean changed = transactionTemplate.execute(status -> anonymizeOne(id, cutoff));
                    if (Boolean.TRUE.equals(changed)) {
                        anonymized++;
                    }
                }
            } while (ids.size() == batchSize);
            if (anonymized > 0) {
                meterRegistry.counter("security.retention.anonymized", "dataset", "users").increment(anonymized);
            }
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.scheduler.failure", "job", "account_anonymization").increment();
            throw ex;
        }
    }

    private boolean anonymizeOne(UUID userId, Instant cutoff) {
        User user = userRepository.findByIdForUpdate(userId).orElse(null);
        if (user == null || user.getAccountState() != AccountState.DELETION_PENDING
                || user.getDeletionRequestedAt() == null
                || user.getDeletionRequestedAt().isAfter(cutoff)) {
            return false;
        }

        String originalEmail = user.getEmail();
        Instant now = Instant.now();
        String anonymizedEmail = "deleted+" + userId.toString().replace("-", "") + "@deleted.authkit.local";
        socialLoginTransactionRepository.deleteByUserId(userId);
        socialIdentityRepository.deleteByUserId(userId);
        List<UUID> oauthRefreshFamilyIds = oauthRefreshTokenFamilyRepository.findByUserIdIn(List.of(userId)).stream()
                .map(io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshTokenFamily::getId)
                .toList();
        if (!oauthRefreshFamilyIds.isEmpty()) {
            oauthRefreshTokenRepository.deleteByFamilyIdIn(oauthRefreshFamilyIds);
        }
        oauthRefreshTokenFamilyRepository.deleteByUserId(userId);
        user.anonymizeForDeletion(anonymizedEmail, now);
        userRepository.save(user);
        securityEventService.record(
                SecurityEventType.ACCOUNT_ANONYMIZED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                userId,
                userId,
                user.getTenantId(),
                originalEmail,
                "account_anonymized_after_grace",
                java.util.Map.of("direct_pii", "email_name"));
        emailOutboxService.deleteByRecipients(List.of(originalEmail));
        tokenStorage.revokeAllSessions(userId.toString());
        userAuthoritiesFilter.evict(userId);
        return true;
    }
}
