package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.annotation.Transactional;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent;
import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.dto.ConsentSnapshotResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEvent;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEvent;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
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
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final MfaService mfaService;

    public AccountLifecycleService(UserRepository userRepository,
                                   SecurityEventRepository securityEventRepository,
                                   ConsentEventRepository consentEventRepository,
                                   OAuthConsentRepository oauthConsentRepository,
                                   SecurityEventService securityEventService,
                                   TokenStorage tokenStorage,
                                   PasswordEncoder passwordEncoder,
                                   AuthProperties authProperties,
                                   MeterRegistry meterRegistry,
                                   Argon2ConcurrencyLimiter argon2Limiter,
                                   UserAuthoritiesFilter userAuthoritiesFilter,
                                   MfaService mfaService) {
        this.userRepository = userRepository;
        this.securityEventRepository = securityEventRepository;
        this.consentEventRepository = consentEventRepository;
        this.oauthConsentRepository = oauthConsentRepository;
        this.securityEventService = securityEventService;
        this.tokenStorage = tokenStorage;
        this.passwordEncoder = passwordEncoder;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
        this.argon2Limiter = argon2Limiter;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.mfaService = mfaService;
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
        verifyStepUp(user,
                stepUpRequest,
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventSeverity.HIGH,
                "data_export_step_up_failed");
        mfaService.requireMfaIfEnabled(user, stepUpRequest.mfaCode(), "data_export");

        var page = PageRequest.of(0, authProperties.getCompliance().getDataExportSecurityEventLimit());
        var securityEvents = securityEventRepository
                .findByTargetUserIdOrderByOccurredAtDesc(user.getId(), page)
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

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "user_data_export_requested");

        return new UserDataExportResponse(
                new UserDataExportResponse.ProfileData(
                        user.getId().toString(),
                        user.getEmail(),
                        user.getName(),
                        user.getPhone(),
                        user.getRole().name(),
                        user.getTenantId().toString(),
                        user.isEmailConfirmed()),
                new UserDataExportResponse.ConsentData(
                        user.isTermsAccepted(),
                        user.isPrivacyPolicyAccepted(),
                        user.getTermsVersion(),
                        user.getPrivacyPolicyVersion(),
                        user.getConsentAcceptedAt(),
                        user.getLawfulBasis()),
                consentEvents,
                oauthConsents,
                new UserDataExportResponse.DeletionData(
                        user.getDeletionRequestedAt(),
                        user.getDeletedAt(),
                        user.getAnonymizedAt()),
                securityEvents);
    }

    @Transactional
    public AccountDeletionResponse requestDeletion(String userId, StepUpRequest stepUpRequest) {
        User user = loadActiveUser(userId);
        verifyStepUp(user,
                stepUpRequest,
                SecurityEventType.ACCOUNT_DELETION_REQUESTED,
                SecurityEventSeverity.HIGH,
                "account_deletion_step_up_failed");
        mfaService.requireMfaIfEnabled(user, stepUpRequest.mfaCode(), "account_deletion");

        Instant now = Instant.now();
        String originalEmail = user.getEmail();
        UUID userUuid = user.getId();
        UUID tenantId = user.getTenantId();

        user.requestDeletion(now);
        String anonymizedEmail = "deleted+" + userUuid.toString().replace("-", "") + "@deleted.authkit.local";
        String anonymizedPassword = encodeWithCapacity(SecureTokenGenerator.randomUrlSafeToken(32));
        user.anonymizeForDeletion(anonymizedEmail, anonymizedPassword, now);
        userRepository.save(user);

        afterCommit(() -> {
            userAuthoritiesFilter.evict(userUuid);
            try {
                tokenStorage.revokeAllSessions(userUuid.toString());
            } catch (RuntimeException ex) {
                meterRegistry.counter("security.infrastructure.failure", "component", "token_storage").increment();
            }

            securityEventService.record(
                    SecurityEventType.ACCOUNT_DELETION_REQUESTED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    userUuid,
                    userUuid,
                    tenantId,
                    originalEmail,
                    "account_deletion_requested",
                    java.util.Map.of("policy", "immediate_anonymization"));
            securityEventService.record(
                    SecurityEventType.ACCOUNT_ANONYMIZED,
                    SecurityEventOutcome.SUCCESS,
                    SecurityEventSeverity.HIGH,
                    userUuid,
                    userUuid,
                    tenantId,
                    originalEmail,
                    "account_anonymized",
                    java.util.Map.of("direct_pii", "email_name_phone"));
        });

        return new AccountDeletionResponse(
                "deleted",
                user.getDeletionRequestedAt(),
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
        if (request == null || request.currentPassword() == null || request.currentPassword().isBlank()) {
            securityEventService.recordForAuthenticatedUser(
                    eventType,
                    SecurityEventOutcome.DENIED,
                    failureSeverity,
                    user,
                    failureReason);
            throw new InvalidCredentialsException();
        }

        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
                securityEventService.recordForAuthenticatedUser(
                        eventType,
                        SecurityEventOutcome.DENIED,
                        failureSeverity,
                        user,
                        failureReason);
                throw new InvalidCredentialsException();
            }
        } finally {
            argon2Limiter.release();
        }
    }

    private String encodeWithCapacity(String rawPassword) {
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            return passwordEncoder.encode(rawPassword);
        } finally {
            argon2Limiter.release();
        }
    }

    private void afterCommit(Runnable action) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            action.run();
            return;
        }

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                action.run();
            }
        });
    }
}
