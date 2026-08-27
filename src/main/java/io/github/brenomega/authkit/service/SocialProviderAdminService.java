package io.github.brenomega.authkit.service;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderCreateRequest;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderResponse;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderUpdateRequest;
import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;
import io.github.brenomega.authkit.domain.social.entity.SocialProviderType;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.exception.InvalidSocialLoginException;
import io.github.brenomega.authkit.exception.MfaRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.SocialSecretCipher;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.SocialIdentityProviderRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.SocialOidcClient;

@Service
public class SocialProviderAdminService {
    private final SocialIdentityProviderRepository providers;
    private final UserRepository users;
    private final PasskeyCredentialRepository passkeys;
    private final StepUpService stepUp;
    private final MfaService mfa;
    private final AuthProperties properties;
    private final SocialSecretCipher cipher;
    private final SocialOidcClient oidc;
    private final SecurityEventService audit;

    public SocialProviderAdminService(SocialIdentityProviderRepository providers, UserRepository users,
            PasskeyCredentialRepository passkeys, StepUpService stepUp, MfaService mfa,
            AuthProperties properties, SocialSecretCipher cipher, SocialOidcClient oidc,
            SecurityEventService audit) {
        this.providers = providers; this.users = users; this.passkeys = passkeys; this.stepUp = stepUp;
        this.mfa = mfa; this.properties = properties; this.cipher = cipher; this.oidc = oidc; this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<AdminSocialProviderResponse> list(Jwt jwt) {
        requireAdmin(jwt);
        return providers.findByOrderByCreatedAtDesc().stream().map(this::response).toList();
    }

    @Transactional
    public AdminSocialProviderResponse create(Jwt jwt, AdminSocialProviderCreateRequest request) {
        User admin = requireAdminStepUp(jwt, request.currentPassword(), request.mfaCode(), "social_provider_create");
        if (request.providerType() == null || request.clientAuthMethod() == null) throw new InvalidSocialLoginException();
        String issuer = normalizeIssuer(request.issuer());
        validateIssuer(issuer, request.providerType());
        validateScopes(request.scopes());
        if (providers.existsByIssuer(issuer) || providers.findByProviderKey(request.providerKey()).isPresent()) {
            throw new InvalidSocialLoginException();
        }
        Instant now = Instant.now();
        SocialIdentityProvider provider = new SocialIdentityProvider(request.providerKey(), request.displayName(),
                request.providerType(), issuer, request.clientId(), cipher.encrypt(request.clientSecret()),
                request.scopes(), request.clientAuthMethod(), now);
        provider = providers.saveAndFlush(provider);
        oidc.metadata(provider); // Reject mismatched issuer or unusable discovery before committing.
        audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_PROVIDER_CREATED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, admin,
                "social_provider_created", java.util.Map.of("provider", provider.getProviderKey(), "issuer", issuer));
        return response(provider);
    }

    @Transactional
    public AdminSocialProviderResponse update(Jwt jwt, UUID id, AdminSocialProviderUpdateRequest request) {
        User admin = requireAdminStepUp(jwt, request.currentPassword(), request.mfaCode(), "social_provider_update");
        SocialIdentityProvider provider = providers.findById(id).orElseThrow(InvalidSocialLoginException::new);
        validateScopes(request.scopes());
        String encrypted = request.clientSecret() == null || request.clientSecret().isBlank()
                ? null : cipher.encrypt(request.clientSecret());
        provider.update(request.displayName(), request.clientId(), encrypted, request.scopes(),
                request.clientAuthMethod() == null ? OidcClientAuthMethod.CLIENT_SECRET_BASIC : request.clientAuthMethod(),
                Instant.now());
        providers.flush();
        oidc.metadata(provider);
        audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_PROVIDER_UPDATED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, admin,
                "social_provider_updated", java.util.Map.of("provider", provider.getProviderKey(),
                        "secret_rotated", Boolean.toString(encrypted != null)));
        return response(provider);
    }

    @Transactional
    public void disable(Jwt jwt, UUID id, String currentPassword, String mfaCode) {
        User admin = requireAdminStepUp(jwt, currentPassword, mfaCode, "social_provider_disable");
        SocialIdentityProvider provider = providers.findById(id).orElseThrow(InvalidSocialLoginException::new);
        provider.disable(Instant.now());
        audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_PROVIDER_UPDATED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, admin,
                "social_provider_disabled", java.util.Map.of("provider", provider.getProviderKey()));
    }

    private User requireAdmin(Jwt jwt) {
        User admin = users.findById(UUID.fromString(jwt.getSubject())).filter(User::isActive)
                .orElseThrow(UserNotFoundException::new);
        if (admin.getRole() != Role.PLATFORM_ADMIN) throw new AccessDeniedException("Admin-plane role required");
        admin.requireEmailConfirmed();
        return admin;
    }
    private User requireAdminStepUp(Jwt jwt, String password, String mfaCode, String reason) {
        User admin = requireAdmin(jwt);
        stepUp.verifyCurrentPassword(admin, password, SecurityEventType.ADMIN_ACTION, reason + "_password_failed");
        boolean hasTotp = mfa.isMfaEnabled(admin);
        boolean hasPasskey = passkeys.countByUserIdAndDisabledAtIsNull(admin.getId()) > 0;
        if (!hasTotp && !hasPasskey) throw new MfaRequiredException();
        List<String> amr = jwt.getClaimAsStringList("amr");
        boolean freshPasskey = amr != null && amr.contains("webauthn") && jwt.getIssuedAt() != null
                && jwt.getIssuedAt().isAfter(Instant.now().minusSeconds(properties.getStepUp().getPasskeyFreshnessSeconds()));
        if (!freshPasskey) {
            if (!hasTotp) throw new MfaRequiredException();
            mfa.requireMfaIfEnabled(admin, mfaCode, reason);
        }
        return admin;
    }
    private void validateIssuer(String issuer, SocialProviderType type) {
        URI uri;
        try { uri = URI.create(issuer); } catch (IllegalArgumentException ex) { throw new InvalidSocialLoginException(); }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getFragment() != null || uri.getQuery() != null) throw new InvalidSocialLoginException();
        Set<String> allowlist = Arrays.stream(properties.getSocial().getIssuerAllowlist().split(","))
                .map(String::trim).filter(v -> !v.isBlank()).collect(Collectors.toSet());
        if (!allowlist.contains(issuer)) throw new InvalidSocialLoginException();
        if (type == SocialProviderType.GOOGLE && !"https://accounts.google.com".equals(issuer)) {
            throw new InvalidSocialLoginException();
        }
    }
    private void validateScopes(Set<String> scopes) {
        if (!scopes.contains("openid") || scopes.stream().anyMatch(s -> !s.matches("[a-zA-Z0-9:._/-]{1,80}"))) {
            throw new InvalidSocialLoginException();
        }
    }
    private String normalizeIssuer(String issuer) { return issuer.trim().replaceAll("/$", ""); }
    private AdminSocialProviderResponse response(SocialIdentityProvider p) {
        return new AdminSocialProviderResponse(p.getId(), p.getProviderKey(), p.getDisplayName(), p.getProviderType(),
                p.getIssuer(), p.getClientId(), p.getScopes(), p.getClientAuthMethod(), p.isEnabled(),
                p.getCreatedAt(), p.getUpdatedAt(), p.getDisabledAt());
    }
}
