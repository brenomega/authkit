package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;
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
import io.github.brenomega.authkit.domain.user.dto.ConsentAcceptanceRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.exception.InvalidConsentVersionException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEvent;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEvent;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.persistence.AfterCommitActions;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectService;
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
import io.github.brenomega.authkit.service.spi.SessionMetadata;

/**
 * Coordinates consent inspection, portable account export, and account deletion.
 *
 * <p>Sensitive lifecycle operations require the same password and configured MFA
 * step-up used for other account-security changes. Exports deliberately contain
 * credential metadata rather than credential secrets and traverse session storage
 * through its bounded cursor protocol. A deletion request is committed with its
 * audit and notification outbox records; revocation of external session state and
 * authority-cache eviction occur at the surrounding service boundary.</p>
 *
 * <p>The service preserves the final active platform administrator and applies
 * immediate anonymization when the configured grace period is zero. Otherwise,
 * {@link AccountAnonymizationService} completes anonymization after the grace
 * period.</p>
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
    private final OAuthLifecycleRevocationService oauthLifecycleRevocationService;
    private final ConsentEventService consentEventService;
    private final SecurityEffectService securityEffectService;

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
                                   PasswordHistoryRepository passwordHistoryRepository,
                                   OAuthLifecycleRevocationService oauthLifecycleRevocationService,
                                   ConsentEventService consentEventService,
                                   SecurityEffectService securityEffectService) {
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
        this.oauthLifecycleRevocationService = oauthLifecycleRevocationService;
        this.consentEventService = consentEventService;
        this.securityEffectService = securityEffectService;
    }

    /** Returns the consent state persisted on the active account. */
    @Transactional(readOnly = true)
    public ConsentSnapshotResponse getConsentSnapshot(String userId) {
        User user = loadActiveUser(userId);
        return toConsentSnapshot(user);
    }

    private ConsentSnapshotResponse toConsentSnapshot(User user) {
        var compliance = authProperties.getCompliance();
        boolean current = hasCurrentConsent(user);
        return new ConsentSnapshotResponse(
                user.isTermsAccepted(),
                user.isPrivacyPolicyAccepted(),
                user.getTermsVersion(),
                user.getPrivacyPolicyVersion(),
                compliance.getTermsVersion(),
                compliance.getPrivacyPolicyVersion(),
                !current,
                user.getConsentAcceptedAt(),
                user.getLawfulBasis());
    }

    /** Atomically accepts the exact current versions and persists both consent and critical audit evidence. */
    @Transactional
    public ConsentSnapshotResponse acceptConsent(String userId, ConsentAcceptanceRequest request) {
        @SuppressWarnings("null")
        User user = userRepository.findByIdForUpdate(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        user.requireEmailConfirmed();
        var compliance = authProperties.getCompliance();
        if (!compliance.getTermsVersion().equals(request.termsVersion())
                || !compliance.getPrivacyPolicyVersion().equals(request.privacyPolicyVersion())) {
            throw new InvalidConsentVersionException();
        }
        if (!hasCurrentConsent(user)) {
            Instant acceptedAt = Instant.now();
            user.acceptConsent(compliance.getTermsVersion(), compliance.getPrivacyPolicyVersion(),
                    compliance.getLawfulBasis(), acceptedAt);
            userRepository.saveAndFlush(user);
            consentEventService.recordCurrentConsent(user);
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.CONSENT_ACCEPTED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    user,
                    "current_policy_versions_accepted",
                    Map.of("terms_version", compliance.getTermsVersion(),
                            "privacy_policy_version", compliance.getPrivacyPolicyVersion()));
            AfterCommitActions.run(() -> userAuthoritiesFilter.evict(user.getId()));
        }
        return toConsentSnapshot(user);
    }

    /** Checks exact configured versions rather than treating historical acceptance as current. */
    public boolean hasCurrentConsent(User user) {
        return user.hasCurrentConsent(authProperties.getCompliance().getTermsVersion(),
                authProperties.getCompliance().getPrivacyPolicyVersion());
    }

    /**
     * Produces a security-sensitive account export after fresh step-up.
     *
     * <p>The export includes audit, consent, authenticator, social-identity, and
     * session metadata, but never password hashes, TOTP secrets, backup-code
     * digests, OAuth secrets, or refresh tokens. Session enumeration is capped at
     * 10,000 entries as an operational safety bound.</p>
     */
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
                .findByTargetUserIdOrderByOccurredAtDesc(
                        user.getId(),
                        PageRequest.of(0, authProperties.getCompliance().getDataExportSecurityEventLimit()))
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
        @SuppressWarnings("null")
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

    private List<SessionMetadata> allSessionMetadata(String userId) {
        List<SessionMetadata> result = new ArrayList<>();
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

    /**
     * Marks an account for deletion and invalidates its ability to authenticate.
     *
     * <p>The last active platform administrator cannot be deleted. With a zero-day
     * grace period, directly identifying data and linked social state are removed
     * in this transaction; otherwise anonymization is deferred until the configured
     * cutoff. Existing sessions are revoked after the durable account transition.</p>
     */
    @Transactional
    public AccountDeletionResponse requestDeletion(String userId, StepUpRequest stepUpRequest) {
        UUID requestedUserId = UUID.fromString(userId);
        userRepository.lockActivePlatformAdministrators(Role.PLATFORM_ADMIN, AccountState.ACTIVE);
        @SuppressWarnings("null")
        User user = userRepository.findByIdForUpdate(requestedUserId)
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        user.requireEmailConfirmed();
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
        Instant graceExpiresAt = now.plus(Duration.ofDays(graceDays));
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
                Map.of("grace_days", Integer.toString(graceDays)));
        oauthLifecycleRevocationService.revokeAll(userUuid, now);
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
                    Map.of("direct_pii", "email_name"));
            emailOutboxService.deleteByRecipients(List.of(originalEmail));
        }

        securityEffectService.invalidateSessions(user, null);
        AfterCommitActions.run(() -> userAuthoritiesFilter.evict(userUuid));

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
