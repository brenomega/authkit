package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.dto.ConsentSnapshotResponse;
import io.github.brenomega.authkit.domain.user.dto.UserDataExportResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEvent;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Account privacy lifecycle operations: export, consent snapshot, and deletion/anonymization.
 */
@Service
public class AccountLifecycleService {

    private final UserRepository userRepository;
    private final SecurityEventRepository securityEventRepository;
    private final SecurityEventService securityEventService;
    private final TokenStorage tokenStorage;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties authProperties;

    public AccountLifecycleService(UserRepository userRepository,
                                   SecurityEventRepository securityEventRepository,
                                   SecurityEventService securityEventService,
                                   TokenStorage tokenStorage,
                                   PasswordEncoder passwordEncoder,
                                   AuthProperties authProperties) {
        this.userRepository = userRepository;
        this.securityEventRepository = securityEventRepository;
        this.securityEventService = securityEventService;
        this.tokenStorage = tokenStorage;
        this.passwordEncoder = passwordEncoder;
        this.authProperties = authProperties;
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
    public UserDataExportResponse exportUserData(String userId) {
        User user = loadActiveUser(userId);
        var page = PageRequest.of(0, authProperties.getCompliance().getDataExportSecurityEventLimit());
        var securityEvents = securityEventRepository
                .findByTargetUserIdOrderByOccurredAtDesc(user.getId(), page)
                .stream()
                .map(this::toExportEvent)
                .toList();

        securityEventService.recordForUser(
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
                new UserDataExportResponse.DeletionData(
                        user.getDeletionRequestedAt(),
                        user.getDeletedAt(),
                        user.getAnonymizedAt()),
                securityEvents);
    }

    @Transactional
    public AccountDeletionResponse requestDeletion(String userId) {
        User user = loadActiveUser(userId);
        Instant now = Instant.now();
        String originalEmail = user.getEmail();
        UUID userUuid = user.getId();
        UUID tenantId = user.getTenantId();

        user.requestDeletion(now);
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

        String anonymizedEmail = "deleted+" + userUuid.toString().replace("-", "") + "@deleted.authkit.local";
        String anonymizedPassword = passwordEncoder.encode(SecureTokenGenerator.randomUrlSafeToken(32));
        user.anonymizeForDeletion(anonymizedEmail, anonymizedPassword, now);
        userRepository.save(user);
        tokenStorage.revokeAllSessions(userUuid.toString());

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
}
