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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUserResponse;
import io.github.brenomega.authkit.domain.user.dto.TenantSummaryResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@Service
public class AdminService {

    private static final int MAX_LIST_LIMIT = 200;
    private static final Pattern SCOPE_PATTERN = Pattern.compile("[a-zA-Z0-9:._/-]{1,80}");

    private final UserRepository userRepository;
    private final OAuthClientRepository oauthClientRepository;
    private final MfaService mfaService;
    private final SecurityEventService securityEventService;

    public AdminService(UserRepository userRepository,
                        OAuthClientRepository oauthClientRepository,
                        MfaService mfaService,
                        SecurityEventService securityEventService) {
        this.userRepository = userRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.mfaService = mfaService;
        this.securityEventService = securityEventService;
    }

    @Transactional(readOnly = true)
    public List<AdminUserResponse> listUsers(int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
        return userRepository.findAll(PageRequest.of(0, boundedLimit, Sort.by("email").ascending()))
                .stream()
                .map(this::toUserResponse)
                .toList();
    }

    @Transactional
    public AdminUserResponse updateRole(Jwt jwt, UUID targetUserId, AdminUpdateRoleRequest request) {
        User admin = requireAdmin(jwt);
        mfaService.requireMfaIfEnabled(admin, request.mfaCode(), "admin_role_change");
        @SuppressWarnings("null")
        User target = userRepository.findById(targetUserId).orElseThrow(UserNotFoundException::new);
        if (target.isDeleted()) {
            throw new UserNotFoundException();
        }
        if (target.getRole() == Role.ADMIN && request.role() != Role.ADMIN
                && userRepository.countByRoleAndDeletedAtIsNull(Role.ADMIN) <= 1) {
            throw new AccessDeniedException("Cannot remove the last active admin");
        }

        target.setRole(request.role());
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
    public List<TenantSummaryResponse> listTenants(int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, MAX_LIST_LIMIT));
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
    public List<AdminOAuthClientResponse> listOAuthClients() {
        return oauthClientRepository.findByOrderByCreatedAtDesc()
                .stream()
                .map(client -> toClientResponse(client, null))
                .toList();
    }

    @Transactional
    public AdminOAuthClientResponse createOAuthClient(Jwt jwt, AdminOAuthClientCreateRequest request) {
        User admin = requireAdmin(jwt);
        mfaService.requireMfaIfEnabled(admin, request.mfaCode(), "admin_oauth_client_create");
        validateRedirectUris(request.redirectUris());
        validateScopes(request.scopes());

        String clientId = "ak_" + SecureTokenGenerator.randomUrlSafeToken(18);
        String rawSecret = request.publicClient() ? null : SecureTokenGenerator.randomUrlSafeToken(32);
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                request.tenantId(),
                clientId,
                rawSecret == null ? null : TokenHasher.sha256Hex(rawSecret),
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
        User admin = requireAdmin(jwt);
        mfaService.requireMfaIfEnabled(admin, request.mfaCode(), "admin_oauth_client_update");
        validateRedirectUris(request.redirectUris());
        validateScopes(request.scopes());

        @SuppressWarnings("null")
        OAuthClient client = oauthClientRepository.findById(clientId)
                .orElseThrow(InvalidOAuthRequestException::new);
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
    public void disableOAuthClient(Jwt jwt, UUID clientId, String mfaCode) {
        User admin = requireAdmin(jwt);
        mfaService.requireMfaIfEnabled(admin, mfaCode, "admin_oauth_client_disable");
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

    private User requireAdmin(Jwt jwt) {
        @SuppressWarnings("null")
        User admin = userRepository.findById(UUID.fromString(jwt.getSubject()))
                .filter(user -> !user.isDeleted())
                .orElseThrow(UserNotFoundException::new);
        if (admin.getRole() != Role.ADMIN) {
            throw new AccessDeniedException("Admin role required");
        }
        admin.requireEmailConfirmed();
        return admin;
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
