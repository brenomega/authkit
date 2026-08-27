package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent;
import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.dto.ConsentSnapshotResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEvent;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEvent;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.SocialLoginTransactionRepository;
import io.github.brenomega.authkit.repository.SocialIdentityProviderRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Account privacy lifecycle operations: export, consent snapshot, and deletion/anonymization.
 */
@Service
public class AccountLifecycleService {

    private final UserRepository userRepository;
    private final SecurityEventRepository securityEventRepository;
    private final ConsentEventRepository consentEventRepository;
    private final OAuthConsentRepository oauthConsentRepository;
    private final SecurityEventService securityEventService;
    private final TokenStorage tokenStorage;
    private final AuthProperties authProperties;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final MfaService mfaService;
    private final StepUpService stepUpService;
    private final EmailOutboxService emailOutboxService;
    private final AbuseThrottleService abuseThrottleService;
    private final SocialIdentityRepository socialIdentityRepository;
    private final SocialLoginTransactionRepository socialLoginTransactionRepository;
    private final SocialIdentityProviderRepository socialIdentityProviderRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final MfaTotpCredentialRepository mfaTotpCredentialRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;

    public AccountLifecycleService(UserRepository userRepository,
                                   SecurityEventRepository securityEventRepository,
                                   ConsentEventRepository consentEventRepository,
                                   OAuthConsentRepository oauthConsentRepository,
                                   SecurityEventService securityEventService,
                                   TokenStorage tokenStorage,
                                   AuthProperties authProperties,
                                   UserAuthoritiesFilter userAuthoritiesFilter,
                                   MfaService mfaService,
                                   StepUpService stepUpService,
                                   EmailOutboxService emailOutboxService,
                                   AbuseThrottleService abuseThrottleService,
                                   SocialIdentityRepository socialIdentityRepository,
                                   SocialLoginTransactionRepository socialLoginTransactionRepository,
                                   SocialIdentityProviderRepository socialIdentityProviderRepository,
                                   PasskeyCredentialRepository passkeyCredentialRepository,
                                   MfaTotpCredentialRepository mfaTotpCredentialRepository,
                                   PasswordHistoryRepository passwordHistoryRepository) {
        this.userRepository = userRepository;
        this.securityEventRepository = securityEventRepository;
        this.consentEventRepository = consentEventRepository;
        this.oauthConsentRepository = oauthConsentRepository;
        this.securityEventService = securityEventService;
        this.tokenStorage = tokenStorage;
        this.authProperties = authProperties;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.mfaService = mfaService;
        this.stepUpService = stepUpService;
        this.emailOutboxService = emailOutboxService;
        this.abuseThrottleService = abuseThrottleService;
        this.socialIdentityRepository = socialIdentityRepository;
        this.socialLoginTransactionRepository = socialLoginTransactionRepository;
        this.socialIdentityProviderRepository = socialIdentityProviderRepository;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.mfaTotpCredentialRepository = mfaTotpCredentialRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
    }

    @Transactional(readOnly = true)
    public ConsentSnapshotResponse getConsentSnapshot(String userId) {
        User user = loadActiveUser(userId);
        return new ConsentSnapshotResponse(
                user.isTermsAccepted(),
                user.isPrivacyPolicyAccepted(),
                user.getTermsVersion(),
                user.getPrivacyPolicyVersion(),
                user.getConsentAcceptedAt(),
                user.getLawfulBasis());
    }

    @Transactional(readOnly = true)
    public UserDataExportResponse exportUserData(String userId, StepUpRequest stepUpRequest) {
        User user = loadActiveUser(userId);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PROFILE_WRITE_USER, user);
        verifyStepUp(user,
                stepUpRequest,
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventSeverity.HIGH,
                "data_export_step_up_failed");
        mfaService.requireMfaIfEnabled(user, stepUpRequest.mfaCode(), "data_export");

        var securityEvents = securityEventRepository
                .findByTargetUserIdOrderByOccurredAtDesc(user.getId())
                .stream()
                .map(this::toExportEvent)
                .toList();
        var consentEvents = consentEventRepository
                .findByUserIdOrderByAcceptedAtDesc(user.getId())
                .stream()
                .map(this::toExportConsentEvent)
                .toList();
        var oauthConsents = oauthConsentRepository
                .findByUserIdOrderByGrantedAtDesc(user.getId())
                .stream()
                .map(this::toExportOAuthConsent)
                .toList();
        var passwordHistory = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(user.getId()).stream()
                .map(entry -> new UserDataExportResponse.PasswordHistoryData(entry.getCreatedAt())).toList();
        var totp = mfaTotpCredentialRepository.findByUserIdOrderByCreatedAtDesc(user.getId()).stream()
                .map(entry -> new UserDataExportResponse.TotpData(entry.getId().toString(), entry.getCreatedAt(),
                        entry.getConfirmedAt(), entry.getDisabledAt())).toList();
        var passkeys = passkeyCredentialRepository.findByUserIdOrderByCreatedAtDesc(user.getId()).stream()
                .map(entry -> new UserDataExportResponse.PasskeyData(entry.getId().toString(), entry.getLabel(),
                        entry.getTransports(), entry.isDiscoverable(), entry.getSignatureCount(), entry.getCreatedAt(),
                        entry.getLastUsedAt(), entry.getDisabledAt())).toList();
        var socialIdentities = socialIdentityRepository.findByUserIdOrderByCreatedAtDesc(user.getId()).stream()
                .map(entry -> new UserDataExportResponse.SocialIdentityData(entry.getId().toString(),
                        socialIdentityProviderRepository.findById(entry.getProviderId())
                                .map(provider -> provider.getProviderKey()).orElse("disabled"),
                        entry.getIssuer(), entry.getEmailAtLink(), entry.isEmailVerified(), entry.getCreatedAt(),
                        entry.getLastLoginAt())).toList();
        var sessions = allSessionMetadata(user.getId().toString()).stream()
                .map(entry -> new UserDataExportResponse.SessionData(entry.publicSessionId(), entry.createdAt(),
                        entry.lastSeenAt(), entry.expiresAt(), entry.initialAmr(), entry.userAgentSummary(),
                        entry.deviceLabel(), entry.creationIpMasked(), entry.lastIpMasked())).toList();

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "user_data_export_requested");

        return new UserDataExportResponse(
                "authkit-user-data-export/v1",
                Instant.now(),
                new UserDataExportResponse.ProfileData(
                        user.getId().toString(),
                        user.getEmail(),
                        user.getName(),
                        user.getRole().name(),
                        user.getTenantId().toString(),
                        user.isEmailConfirmed(),
                        user.getAccountState().name(),
                        user.getSuspendedAt(),
                        user.getSuspensionReason(),
                        user.getPendingEmail(),
                        user.getEmailChangeRequestedAt(),
                        user.getEmailChangeExpiresAt()),
                new UserDataExportResponse.ConsentData(
                        user.isTermsAccepted(),
                        user.isPrivacyPolicyAccepted(),
                        user.getTermsVersion(),
                        user.getPrivacyPolicyVersion(),
                        user.getConsentAcceptedAt(),
                        user.getLawfulBasis()),
                consentEvents,
                oauthConsents,
                new UserDataExportResponse.CredentialData(user.getPassword() != null, passwordHistory,
                        totp, passkeys, socialIdentities),
                sessions,
                new UserDataExportResponse.DeletionData(
                        user.getDeletionRequestedAt(),
                        user.getDeletedAt(),
                        user.getAnonymizedAt()),
                securityEvents);
    }

    private List<io.github.brenomega.authkit.service.spi.SessionMetadata> allSessionMetadata(String userId) {
        List<io.github.brenomega.authkit.service.spi.SessionMetadata> result = new java.util.ArrayList<>();
        String cursor = null;
        do {
            var page = tokenStorage.listSessions(userId, 100, cursor);
            result.addAll(page.items());
            cursor = page.nextCursor();
            if (result.size() > 10_000) {
                throw new IllegalStateException("Session export exceeds the supported safety bound");
            }
        } while (cursor != null);
        return List.copyOf(result);
    }

    @Transactional
    public AccountDeletionResponse requestDeletion(String userId, StepUpRequest stepUpRequest) {
        User user = loadActiveUser(userId);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.ACCOUNT_DELETION_USER, user);
        verifyStepUp(user,
                stepUpRequest,
                SecurityEventType.ACCOUNT_DELETION_REQUESTED,
                SecurityEventSeverity.HIGH,
                "account_deletion_step_up_failed");
        mfaService.requireMfaIfEnabled(user, stepUpRequest.mfaCode(), "account_deletion");

        if (user.getRole() == Role.PLATFORM_ADMIN
                && userRepository.countByRoleAndAccountState(Role.PLATFORM_ADMIN, AccountState.ACTIVE) <= 1) {
            throw new AccessDeniedException("Cannot delete the last active platform administrator");
        }

        Instant now = Instant.now();
        String originalEmail = user.getEmail();
        UUID userUuid = user.getId();
        UUID tenantId = user.getTenantId();

        user.requestDeletion(now);
        int graceDays = authProperties.getCompliance().getDeletionGracePeriodDays();
        Instant graceExpiresAt = now.plus(java.time.Duration.ofDays(graceDays));
        if (graceDays == 0) {
            socialLoginTransactionRepository.deleteByUserId(userUuid);
            socialIdentityRepository.deleteByUserId(userUuid);
            String anonymizedEmail = "deleted+" + userUuid.toString().replace("-", "") + "@deleted.authkit.local";
            user.anonymizeForDeletion(anonymizedEmail, now);
        }
        userRepository.save(user);

        securityEventService.record(
                SecurityEventType.ACCOUNT_DELETION_REQUESTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                userUuid,
                userUuid,
                tenantId,
                originalEmail,
                "account_deletion_requested",
                java.util.Map.of("grace_days", Integer.toString(graceDays)));
        if (graceDays == 0) {
            securityEventService.record(
                    SecurityEventType.ACCOUNT_ANONYMIZED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    userUuid,
                    userUuid,
                    tenantId,
                    originalEmail,
                    "account_anonymized",
                    java.util.Map.of("direct_pii", "email_name"));
            emailOutboxService.deleteByRecipients(java.util.List.of(originalEmail));
        }

        tokenStorage.revokeAllSessions(userUuid.toString());
        userAuthoritiesFilter.evict(userUuid);

        return new AccountDeletionResponse(
                graceDays == 0 ? "anonymized" : "deletion_pending",
                user.getDeletionRequestedAt(),
                graceExpiresAt,
                user.getDeletedAt(),
                user.getAnonymizedAt());
    }

    private User loadActiveUser(String userId) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        if (user.isDeleted()) {
            throw new UserNotFoundException();
        }
        user.requireEmailConfirmed();
        return user;
    }

    private void requireTenantAccess(User user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return;
        }

        String tenantId = JwtTenantResolver.extractTenantId(jwt);
        if (tenantId == null || !tenantId.equals(user.getTenantId().toString())) {
            throw new UserNotFoundException();
        }
    }

    private UserDataExportResponse.SecurityEventData toExportEvent(SecurityEvent event) {
        return new UserDataExportResponse.SecurityEventData(
                event.getOccurredAt(),
                event.getEventType().name(),
                event.getOutcome().name(),
                event.getSeverity().name(),
                event.getEmailMasked(),
                event.getClientIpMasked(),
                event.getRequestMethod(),
                event.getRequestPath(),
                event.getReason());
    }

    private UserDataExportResponse.ConsentEventData toExportConsentEvent(ConsentEvent event) {
        return new UserDataExportResponse.ConsentEventData(
                event.getTermsVersion(),
                event.getPrivacyPolicyVersion(),
                event.getLawfulBasis(),
                event.getAcceptedAt(),
                event.getRecordedAt(),
                event.getEventHash());
    }

    private UserDataExportResponse.OAuthConsentData toExportOAuthConsent(OAuthConsent consent) {
        return new UserDataExportResponse.OAuthConsentData(
                consent.getClientId(),
                List.copyOf(consent.getScopes()),
                consent.getGrantedAt(),
                consent.getRevokedAt());
    }

    private void verifyStepUp(User user,
                              StepUpRequest request,
                              SecurityEventType eventType,
                              SecurityEventSeverity failureSeverity,
                              String failureReason) {
        stepUpService.verifyCurrentPassword(
                user,
                request == null ? null : request.currentPassword(),
                eventType,
                failureSeverity,
                failureReason);
    }

}
