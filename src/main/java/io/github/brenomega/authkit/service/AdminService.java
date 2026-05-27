package io.github.brenomega.authkit.service;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUserResponse;
import io.github.brenomega.authkit.domain.user.dto.TenantSummaryResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.MfaRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
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

    public AdminService(UserRepository userRepository,
                        OAuthClientRepository oauthClientRepository,
                        MfaService mfaService,
                        SecurityEventService securityEventService,
                        PasswordEncoder passwordEncoder,
                        PasskeyCredentialRepository passkeyCredentialRepository,
                        StepUpService stepUpService,
                        TokenStorage tokenStorage,
                        UserAuthoritiesFilter userAuthoritiesFilter,
                        AuthProperties authProperties) {
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
    }

    @Transactional(readOnly = true)
    public List<AdminUserResponse> listUsers(Jwt jwt, int limit) {
        User admin = requireAdminPlanePrincipal(jwt);
        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
        if (admin.getRole() == Role.TENANT_ADMIN) {
            return userRepository.findByTenantIdAndDeletedAtIsNull(
                            admin.getTenantId(),
                            PageRequest.of(0, boundedLimit, Sort.by("email").ascending()))
                    .stream()
                    .map(this::toUserResponse)
                    .toList();
        }
        return userRepository.findAll(PageRequest.of(0, boundedLimit, Sort.by("email").ascending()))
                .stream()
                .map(this::toUserResponse)
                .toList();
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
        if (target.getRole() == Role.ADMIN && request.role() != Role.ADMIN
                && userRepository.countByRoleAndDeletedAtIsNull(Role.ADMIN) <= 1) {
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

    @Transactional(readOnly = true)
    public List<TenantSummaryResponse> listTenants(Jwt jwt, int limit) {
        User admin = requireAdminPlanePrincipal(jwt);
        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
        if (admin.getRole() == Role.TENANT_ADMIN) {
            return List.of(new TenantSummaryResponse(
                    admin.getTenantId(),
                    admin.getId(),
                    admin.getEmail(),
                    admin.getRole()));
        }
        return userRepository.findAll(PageRequest.of(0, boundedLimit, Sort.by("email").ascending()))
                .stream()
                .filter(user -> !user.isDeleted())
                .map(user -> new TenantSummaryResponse(
                        user.getTenantId(),
                        user.getId(),
                        user.getEmail(),
                        user.getRole()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<AdminOAuthClientResponse> listOAuthClients(Jwt jwt) {
        User admin = requireAdminPlanePrincipal(jwt);
        if (admin.getRole() == Role.TENANT_ADMIN) {
            return oauthClientRepository.findByTenantIdOrderByCreatedAtDesc(admin.getTenantId())
                    .stream()
                    .map(client -> toClientResponse(client, null))
                    .toList();
        }
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
        UUID tenantId = requireCreatableClientTenant(admin, request.tenantId());

        String clientId = "ak_" + SecureTokenGenerator.randomUrlSafeToken(18);
        String rawSecret = request.publicClient() ? null : SecureTokenGenerator.randomUrlSafeToken(32);
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                tenantId,
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
        requireCanManageClient(admin, client);
        client.update(request.displayName(), request.redirectUris(), request.scopes(), true, Instant.now());

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_CLIENT_UPDATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                admin,
                "oauth_client_updated",
                java.util.Map.of("client_id", client.getClientId()));

        return toClientResponse(client, null);
    }

    @Transactional
    public void disableOAuthClient(Jwt jwt, UUID clientId, String currentPassword, String mfaCode) {
        User admin = requireAdminPlanePrincipal(jwt);
        requireAdminWriteStepUp(jwt, admin, currentPassword, mfaCode, "admin_oauth_client_disable");
        @SuppressWarnings("null")
        OAuthClient client = oauthClientRepository.findById(clientId)
                .orElseThrow(InvalidOAuthRequestException::new);
        requireCanManageClient(admin, client);
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
                .filter(user -> !user.isDeleted())
                .orElseThrow(UserNotFoundException::new);
        if (admin.getRole() != Role.ADMIN && admin.getRole() != Role.TENANT_ADMIN) {
            throw new AccessDeniedException("Admin-plane role required");
        }
        admin.requireEmailConfirmed();
        return admin;
    }

    private void requireAdminWriteStepUp(Jwt jwt, User admin, String currentPassword, String mfaCode, String reason) {
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
        if (admin.getRole() == Role.ADMIN) {
            return;
        }
        if (!admin.getTenantId().equals(target.getTenantId())) {
            throw new UserNotFoundException();
        }
        if (target.getId().equals(admin.getId())) {
            throw new AccessDeniedException("Tenant administrators cannot change their own role");
        }
        if (target.getRole() == Role.ADMIN
                || target.getRole() == Role.TENANT_ADMIN
                || requestedRole == Role.ADMIN
                || requestedRole == Role.TENANT_ADMIN) {
            throw new AccessDeniedException("Tenant administrators cannot manage platform or tenant administrators");
        }
    }

    private UUID requireCreatableClientTenant(User admin, UUID requestedTenantId) {
        if (admin.getRole() == Role.ADMIN) {
            return requestedTenantId;
        }
        if (requestedTenantId != null && !admin.getTenantId().equals(requestedTenantId)) {
            throw new InvalidOAuthRequestException();
        }
        return admin.getTenantId();
    }

    private void requireCanManageClient(User admin, OAuthClient client) {
        if (admin.getRole() == Role.ADMIN) {
            return;
        }
        if (client.getTenantId() == null || !client.getTenantId().equals(admin.getTenantId())) {
            throw new InvalidOAuthRequestException();
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
                user.isEmailConfirmed(),
                user.isDeleted(),
                user.getDeletionRequestedAt(),
                user.getDeletedAt(),
                user.getAnonymizedAt());
    }

    private AdminOAuthClientResponse toClientResponse(OAuthClient client, String rawSecret) {
        return new AdminOAuthClientResponse(
                client.getId(),
                client.getTenantId(),
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
