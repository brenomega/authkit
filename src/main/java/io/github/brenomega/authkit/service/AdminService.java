package io.github.brenomega.authkit.service;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.EnumMap;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientResponse;
import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUserResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminUserPageResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminUserDetailResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminAuthenticatorStatus;
import io.github.brenomega.authkit.domain.user.dto.AdminSecurityEventResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminSecurityEventPageResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminOperationalStatusResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminAccountStateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.MfaRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxStatus;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.infrastructure.security.AdminCursorCodec;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@Service
public class AdminService {

    private static final int MAX_LIST_LIMIT = 200;
    private static final Pattern SCOPE_PATTERN = Pattern.compile("[a-zA-Z0-9:._/-]{1,80}");

    private final UserRepository userRepository;
    private final OAuthClientRepository oauthClientRepository;
    private final MfaService mfaService;
    private final SecurityEventService securityEventService;
    private final PasswordEncoder passwordEncoder;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final StepUpService stepUpService;
    private final TokenStorage tokenStorage;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final AuthProperties authProperties;
    private final AbuseThrottleService abuseThrottleService;
    private final MfaTotpCredentialRepository mfaTotpCredentialRepository;
    private final SocialIdentityRepository socialIdentityRepository;
    private final SecurityEventRepository securityEventRepository;
    private final EmailOutboxRepository emailOutboxRepository;
    private final AdminCursorCodec adminCursorCodec;

    public AdminService(UserRepository userRepository,
                        OAuthClientRepository oauthClientRepository,
                        MfaService mfaService,
                        SecurityEventService securityEventService,
                        PasswordEncoder passwordEncoder,
                        PasskeyCredentialRepository passkeyCredentialRepository,
                        StepUpService stepUpService,
                        TokenStorage tokenStorage,
                        UserAuthoritiesFilter userAuthoritiesFilter,
                        AuthProperties authProperties,
                        AbuseThrottleService abuseThrottleService,
                        MfaTotpCredentialRepository mfaTotpCredentialRepository,
                        SocialIdentityRepository socialIdentityRepository,
                        SecurityEventRepository securityEventRepository,
                        EmailOutboxRepository emailOutboxRepository,
                        AdminCursorCodec adminCursorCodec) {
        this.userRepository = userRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.mfaService = mfaService;
        this.securityEventService = securityEventService;
        this.passwordEncoder = passwordEncoder;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
        this.stepUpService = stepUpService;
        this.tokenStorage = tokenStorage;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.authProperties = authProperties;
        this.abuseThrottleService = abuseThrottleService;
        this.mfaTotpCredentialRepository = mfaTotpCredentialRepository;
        this.socialIdentityRepository = socialIdentityRepository;
        this.securityEventRepository = securityEventRepository;
        this.emailOutboxRepository = emailOutboxRepository;
        this.adminCursorCodec = adminCursorCodec;
    }

    @Transactional(readOnly = true)
    public AdminUserPageResponse listUsers(Jwt jwt, String search, int limit, String cursor) {
        requireAdminPlanePrincipal(jwt);
        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
        String normalizedSearch = search == null ? "" : search.strip().toLowerCase(java.util.Locale.ROOT);
        var position = adminCursorCodec.decode(cursor, "users", boundedLimit, normalizedSearch);
        var page = userRepository.searchForAdministration(normalizedSearch,
                PageRequest.of(position.page(), boundedLimit,
                        Sort.by(Sort.Order.asc("email"), Sort.Order.asc("id"))));
        var items = page.getContent().stream()
                .map(this::toUserResponse)
                .toList();
        String nextCursor = page.hasNext()
                ? adminCursorCodec.issue("users", position.page() + 1, boundedLimit, normalizedSearch)
                : null;
        return new AdminUserPageResponse(items, nextCursor);
    }

    @Transactional(readOnly = true)
    public AdminUserDetailResponse getUser(Jwt jwt, UUID targetUserId) {
        requireAdminPlanePrincipal(jwt);
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        return new AdminUserDetailResponse(toUserResponse(target), new AdminAuthenticatorStatus(
                target.getPassword() != null,
                mfaTotpCredentialRepository.countByUserIdAndConfirmedTrueAndDisabledAtIsNull(target.getId()),
                passkeyCredentialRepository.countByUserIdAndDisabledAtIsNull(target.getId()),
                socialIdentityRepository.countByUserId(target.getId())));
    }

    @Transactional
    public void revokeAllUserSessions(Jwt jwt, UUID targetUserId, String currentPassword, String mfaCode) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, currentPassword, mfaCode, "admin_user_sessions_revoke");
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        tokenStorage.revokeAllSessions(target.getId().toString());
        securityEventService.record(SecurityEventType.ADMIN_ACTION, SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH, admin.getId(), target.getId(), target.getTenantId(),
                target.getEmail(), "admin_revoked_all_user_sessions", java.util.Map.of());
    }

    @Transactional(readOnly = true)
    public AdminSecurityEventPageResponse listSecurityEvents(Jwt jwt, UUID userId, int limit, String cursor) {
        requireAdminPlanePrincipal(jwt);
        int boundedLimit = Math.max(1, Math.min(limit, 200));
        String binding = userId == null ? "all" : userId.toString();
        var position = adminCursorCodec.decode(cursor, "events", boundedLimit, binding);
        var page = securityEventRepository.searchForAdministration(userId,
                PageRequest.of(position.page(), boundedLimit,
                        Sort.by(Sort.Order.desc("occurredAt"), Sort.Order.desc("id"))));
        var items = page.getContent().stream().map(event -> new AdminSecurityEventResponse(
                event.getId(), event.getOccurredAt(), event.getEventType(), event.getOutcome(),
                event.getSeverity(), event.getActorUserId(), event.getTargetUserId(),
                event.getEmailMasked(), event.getClientIpMasked(), event.getReason(), event.getMetadataJson()))
                .toList();
        String next = page.hasNext()
                ? adminCursorCodec.issue("events", position.page() + 1, boundedLimit, binding)
                : null;
        return new AdminSecurityEventPageResponse(items, next);
    }

    @Transactional(readOnly = true)
    public AdminOperationalStatusResponse operationalStatus(Jwt jwt) {
        requireAdminPlanePrincipal(jwt);
        EnumMap<EmailOutboxStatus, Long> counts = new EnumMap<>(EmailOutboxStatus.class);
        for (EmailOutboxStatus status : EmailOutboxStatus.values()) {
            counts.put(status, emailOutboxRepository.countByStatus(status));
        }
        return new AdminOperationalStatusResponse(
                counts.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                        entry -> entry.getKey().name(), java.util.Map.Entry::getValue)),
                authProperties.getEmailOutbox().getDispatchMode(),
                authProperties.getTokenStorage().getBackend(),
                authProperties.getCompliance().isRetentionJobEnabled());
    }

    @Transactional
    public AdminUserResponse updateRole(Jwt jwt, UUID targetUserId, AdminUpdateRoleRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_role_change");
        @SuppressWarnings("null")
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        if (target.isDeleted()) {
            throw new UserNotFoundException();
        }
        requireCanManageUser(admin, target, request.role());
        if (target.getRole() == Role.PLATFORM_ADMIN && request.role() != Role.PLATFORM_ADMIN
                && userRepository.countByRoleAndAccountState(Role.PLATFORM_ADMIN, AccountState.ACTIVE) <= 1) {
            throw new AccessDeniedException("Cannot remove the last active admin");
        }

        target.setRole(request.role());
        userRepository.save(target);
        tokenStorage.revokeAllSessions(target.getId().toString());
        userAuthoritiesFilter.evict(target.getId());
        securityEventService.record(
                SecurityEventType.ADMIN_ACTION,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin.getId(),
                target.getId(),
                target.getTenantId(),
                target.getEmail(),
                "admin_role_updated",
                java.util.Map.of("role", request.role().name()));
        return toUserResponse(target);
    }

    @Transactional
    public AdminUserResponse suspendUser(Jwt jwt, UUID targetUserId, AdminAccountStateRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_user_suspend");
        @SuppressWarnings("null")
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        if (target.isDeleted()) {
            throw new UserNotFoundException();
        }
        if (target.getRole() == Role.PLATFORM_ADMIN
                && target.isActive()
                && userRepository.countByRoleAndAccountState(Role.PLATFORM_ADMIN, AccountState.ACTIVE) <= 1) {
            throw new AccessDeniedException("Cannot suspend the last active platform administrator");
        }

        target.suspend(request.reason(), Instant.now());
        userRepository.save(target);
        securityEventService.record(
                SecurityEventType.ACCOUNT_SUSPENDED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin.getId(),
                target.getId(),
                target.getTenantId(),
                target.getEmail(),
                "account_suspended_by_platform_admin",
                java.util.Map.of());
        tokenStorage.revokeAllSessions(target.getId().toString());
        userAuthoritiesFilter.evict(target.getId());
        return toUserResponse(target);
    }

    @Transactional
    public AdminUserResponse reactivateUser(Jwt jwt, UUID targetUserId, AdminAccountStateRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_user_reactivate");
        @SuppressWarnings("null")
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        target.reactivate();
        userRepository.save(target);
        securityEventService.record(
                SecurityEventType.ACCOUNT_REACTIVATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin.getId(),
                target.getId(),
                target.getTenantId(),
                target.getEmail(),
                "account_reactivated_by_platform_admin",
                java.util.Map.of());
        userAuthoritiesFilter.evict(target.getId());
        return toUserResponse(target);
    }

    @Transactional
    public AdminUserResponse cancelDeletion(Jwt jwt, UUID targetUserId, AdminAccountStateRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_deletion_cancel");
        @SuppressWarnings("null")
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        target.cancelDeletion();
        userRepository.save(target);
        securityEventService.record(
                SecurityEventType.ACCOUNT_DELETION_CANCELLED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin.getId(),
                target.getId(),
                target.getTenantId(),
                target.getEmail(),
                "account_deletion_cancelled_by_platform_admin",
                java.util.Map.of());
        userAuthoritiesFilter.evict(target.getId());
        return toUserResponse(target);
    }

    @Transactional(readOnly = true)
    public List<AdminOAuthClientResponse> listOAuthClients(Jwt jwt) {
        requireAdminPlanePrincipal(jwt);
        return oauthClientRepository.findByOrderByCreatedAtDesc()
                .stream()
                .map(client -> toClientResponse(client, null))
                .toList();
    }

    @Transactional
    public AdminOAuthClientResponse createOAuthClient(Jwt jwt, AdminOAuthClientCreateRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_oauth_client_create");
        validateRedirectUris(request.redirectUris());
        validateScopes(request.scopes());
        String clientId = "ak_" + SecureTokenGenerator.randomUrlSafeToken(18);
        String rawSecret = request.publicClient() ? null : SecureTokenGenerator.randomUrlSafeToken(32);
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                clientId,
                rawSecret == null ? null : passwordEncoder.encode(rawSecret),
                request.publicClient(),
                request.displayName(),
                request.redirectUris(),
                request.scopes(),
                true,
                Instant.now()));

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_CLIENT_CREATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin,
                "oauth_client_created",
                java.util.Map.of("client_id", client.getClientId()));

        return toClientResponse(client, rawSecret);
    }

    @Transactional
    public AdminOAuthClientResponse updateOAuthClient(Jwt jwt, UUID clientId, AdminOAuthClientUpdateRequest request) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, request.currentPassword(), request.mfaCode(), "admin_oauth_client_update");
        validateRedirectUris(request.redirectUris());
        validateScopes(request.scopes());

        @SuppressWarnings("null")
        OAuthClient client = oauthClientRepository.findById(clientId)
                .orElseThrow(InvalidOAuthRequestException::new);
        client.update(request.displayName(), request.redirectUris(), request.scopes(), true, Instant.now());
        String rawSecret = null;
        if (request.rotateSecret()) {
            if (client.isPublicClient()) {
                throw new InvalidOAuthRequestException();
            }
            rawSecret = SecureTokenGenerator.randomUrlSafeToken(32);
            client.rotateSecret(passwordEncoder.encode(rawSecret), Instant.now());
        }

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_CLIENT_UPDATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin,
                "oauth_client_updated",
                java.util.Map.of("client_id", client.getClientId(), "secret_rotated", Boolean.toString(request.rotateSecret())));

        return toClientResponse(client, rawSecret);
    }

    @Transactional
    public void disableOAuthClient(Jwt jwt, UUID clientId, String currentPassword, String mfaCode) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, currentPassword, mfaCode, "admin_oauth_client_disable");
        @SuppressWarnings("null")
        OAuthClient client = oauthClientRepository.findById(clientId)
                .orElseThrow(InvalidOAuthRequestException::new);
        client.disable(Instant.now());

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_CLIENT_UPDATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin,
                "oauth_client_disabled",
                java.util.Map.of("client_id", client.getClientId()));
    }

    private User requireAdminPlanePrincipal(Jwt jwt) {
        @SuppressWarnings("null")
        User admin = userRepository.findById(UUID.fromString(jwt.getSubject()))
                .filter(User::isActive)
                .orElseThrow(UserNotFoundException::new);
        if (admin.getRole() != Role.PLATFORM_ADMIN) {
            throw new AccessDeniedException("Admin-plane role required");
        }
        admin.requireEmailConfirmed();
        return admin;
    }

    private void requireAdminWriteStepUp(Jwt jwt, User admin, String currentPassword, String mfaCode, String reason) {
        abuseThrottleService.checkTenant(AbuseRateLimitPolicy.ADMIN_WRITE_TENANT, admin.getTenantId());
        stepUpService.verifyCurrentPassword(admin, currentPassword, SecurityEventType.ADMIN_ACTION, reason + "_password_step_up_failed");

        boolean hasTotp = mfaService.isMfaEnabled(admin);
        boolean hasPasskey = passkeyCredentialRepository.countByUserIdAndDisabledAtIsNull(admin.getId()) > 0;
        if (!hasTotp && !hasPasskey) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.ADMIN_ACTION,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    admin,
                    reason + "_admin_second_factor_missing");
            throw new MfaRequiredException();
        }

        if (hasFreshPasskeyAuthentication(jwt)) {
            return;
        }

        if (hasTotp) {
            mfaService.requireMfaIfEnabled(admin, mfaCode, reason);
            return;
        }

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.ADMIN_ACTION,
                SecurityEventOutcome.DENIED,
                SecurityEventSeverity.HIGH,
                admin,
                reason + "_fresh_passkey_required");
        throw new MfaRequiredException();
    }

    private boolean hasFreshPasskeyAuthentication(Jwt jwt) {
        List<String> amr = jwt.getClaimAsStringList("amr");
        if (amr == null || amr.stream().noneMatch(method -> "webauthn".equalsIgnoreCase(method))) {
            return false;
        }
        Instant issuedAt = jwt.getIssuedAt();
        return issuedAt != null
                && issuedAt.isAfter(Instant.now().minusSeconds(authProperties.getStepUp().getPasskeyFreshnessSeconds()));
    }

    private void requireCanManageUser(User admin, User target, Role requestedRole) {
        if (admin.getRole() != Role.PLATFORM_ADMIN) {
            throw new AccessDeniedException("Platform administrator role required");
        }
    }

    private void validateRedirectUris(Set<String> redirectUris) {
        redirectUris.forEach(uri -> {
            URI parsed;
            try {
                parsed = URI.create(uri);
            } catch (IllegalArgumentException ex) {
                throw new InvalidOAuthRequestException();
            }
            String scheme = parsed.getScheme();
            String host = parsed.getHost();
            if (scheme == null || host == null) {
                throw new InvalidOAuthRequestException();
            }
            boolean localhost = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
            if (!"https".equalsIgnoreCase(scheme) && !(localhost && "http".equalsIgnoreCase(scheme))) {
                throw new InvalidOAuthRequestException();
            }
        });
    }

    private void validateScopes(Set<String> scopes) {
        scopes.forEach(scope -> {
            if (!SCOPE_PATTERN.matcher(scope).matches()) {
                throw new InvalidOAuthRequestException();
            }
        });
    }

    private AdminUserResponse toUserResponse(User user) {
        return new AdminUserResponse(
                user.getId(),
                user.getTenantId(),
                user.getEmail(),
                user.getName(),
                user.getRole(),
                user.getAccountState(),
                user.isEmailConfirmed(),
                user.getSuspendedAt(),
                user.getSuspensionReason(),
                user.getDeletionRequestedAt(),
                user.getDeletedAt(),
                user.getAnonymizedAt());
    }

    private AdminOAuthClientResponse toClientResponse(OAuthClient client, String rawSecret) {
        return new AdminOAuthClientResponse(
                client.getId(),
                client.getClientId(),
                rawSecret,
                client.isPublicClient(),
                client.getDisplayName(),
                client.getRedirectUris(),
                client.getScopes(),
                client.isRequirePkce(),
                client.isEnabled(),
                client.getCreatedAt(),
                client.getUpdatedAt(),
                client.getDisabledAt());
    }
}
