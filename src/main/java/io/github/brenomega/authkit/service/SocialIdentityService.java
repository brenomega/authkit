package io.github.brenomega.authkit.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import io.github.brenomega.authkit.domain.social.dto.SocialAuthorizationResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialCallbackResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialIdentityResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialLoginStartRequest;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentity;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;
import io.github.brenomega.authkit.domain.social.entity.SocialLoginPurpose;
import io.github.brenomega.authkit.domain.social.entity.SocialLoginTransaction;
import io.github.brenomega.authkit.domain.social.entity.SocialProviderType;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidSocialLoginException;
import io.github.brenomega.authkit.exception.LastAuthenticatorException;
import io.github.brenomega.authkit.exception.SocialLinkRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.SocialSecretCipher;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.SocialIdentityProviderRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.SocialLoginTransactionRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.SocialOidcClient;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@Service
public class SocialIdentityService {
    private final SocialIdentityProviderRepository providers;
    private final SocialIdentityRepository identities;
    private final SocialLoginTransactionRepository transactions;
    private final UserRepository users;
    private final PasskeyCredentialRepository passkeys;
    private final SocialOidcClient oidcClient;
    private final SocialSecretCipher cipher;
    private final AuthProperties properties;
    private final AuthService authService;
    private final StepUpService stepUpService;
    private final MfaService mfaService;
    private final TokenStorage tokenStorage;
    private final SecurityEventService audit;

    public SocialIdentityService(SocialIdentityProviderRepository providers, SocialIdentityRepository identities,
            SocialLoginTransactionRepository transactions, UserRepository users,
            PasskeyCredentialRepository passkeys, SocialOidcClient oidcClient, SocialSecretCipher cipher,
            AuthProperties properties, AuthService authService, StepUpService stepUpService,
            MfaService mfaService, TokenStorage tokenStorage, SecurityEventService audit) {
        this.providers = providers; this.identities = identities; this.transactions = transactions;
        this.users = users; this.passkeys = passkeys; this.oidcClient = oidcClient; this.cipher = cipher;
        this.properties = properties; this.authService = authService; this.stepUpService = stepUpService;
        this.mfaService = mfaService; this.tokenStorage = tokenStorage; this.audit = audit;
    }

    @Transactional
    public SocialAuthorizationResponse startLogin(String providerKey, SocialLoginStartRequest request) {
        boolean terms = request != null && request.termsAccepted();
        boolean privacy = request != null && request.privacyPolicyAccepted();
        return start(providerKey, SocialLoginPurpose.LOGIN, null, terms, privacy);
    }

    @Transactional
    public SocialAuthorizationResponse startLink(String providerKey, Jwt jwt, StepUpRequest request) {
        User user = activeUserForUpdate(UUID.fromString(jwt.getSubject()));
        requireStrongStepUp(user, jwt, request, "social_link");
        return start(providerKey, SocialLoginPurpose.LINK, user.getId(), true, true);
    }

    private SocialAuthorizationResponse start(String providerKey, SocialLoginPurpose purpose, UUID userId,
                                              boolean terms, boolean privacy) {
        ensureEnabled();
        SocialIdentityProvider provider = enabledProvider(providerKey);
        var metadata = oidcClient.metadata(provider);
        String state = SecureTokenGenerator.randomUrlSafeToken(32);
        String nonce = SecureTokenGenerator.randomUrlSafeToken(32);
        String verifier = SecureTokenGenerator.randomUrlSafeToken(64);
        Instant now = Instant.now();
        long ttlSeconds = properties.getSocial().getTransactionTtlMinutes() * 60;
        transactions.save(new SocialLoginTransaction(TokenHasher.sha256Hex(state), provider.getId(), purpose,
                userId, nonce, cipher.encrypt(verifier), terms, privacy, now, now.plusSeconds(ttlSeconds)));

        String url = UriComponentsBuilder.fromUriString(metadata.authorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", provider.getClientId())
                .queryParam("redirect_uri", callbackUri(provider))
                .queryParam("scope", String.join(" ", provider.getScopes()))
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .build().encode().toUriString();

        audit.record(SecurityEventType.SOCIAL_LOGIN_STARTED, SecurityEventOutcome.INFO,
                SecurityEventSeverity.LOW, userId, userId, null, null,
                purpose == SocialLoginPurpose.LOGIN ? "social_login_started" : "social_link_started",
                java.util.Map.of("provider", provider.getProviderKey()));
        return new SocialAuthorizationResponse(url, ttlSeconds);
    }

    @Transactional
    public CallbackResult callback(String providerKey, String state, String code) {
        ensureEnabled();
        if (state == null || state.isBlank() || code == null || code.isBlank()) throw new InvalidSocialLoginException();
        SocialIdentityProvider provider = enabledProvider(providerKey);
        SocialLoginTransaction transaction = transactions
                .findByStateHashAndProviderId(TokenHasher.sha256Hex(state), provider.getId())
                .orElseThrow(InvalidSocialLoginException::new);
        Instant now = Instant.now();
        if (transactions.consume(transaction.getId(), now) != 1) throw new InvalidSocialLoginException();

        var identity = oidcClient.exchangeAndVerify(provider, code,
                cipher.decrypt(transaction.getEncryptedVerifier()), callbackUri(provider), transaction.getNonce());
        if (!provider.getIssuer().equals(identity.issuer())) throw new InvalidSocialLoginException();

        if (transaction.getPurpose() == SocialLoginPurpose.LINK) {
            User user = activeUserForUpdate(transaction.getUserId());
            link(user, provider, identity, now);
            tokenStorage.revokeAllSessions(user.getId().toString());
            audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_IDENTITY_LINKED,
                    SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, user,
                    "social_identity_linked", java.util.Map.of("provider", provider.getProviderKey()));
            return new CallbackResult(SocialCallbackResponse.linked(), null);
        }

        User user = resolveLoginUser(provider, identity, transaction, now);
        AuthService.LoginResult login = authService.beginFederatedLogin(user, provider.getProviderKey());
        return new CallbackResult(SocialCallbackResponse.authenticated(login.response()), login.refreshToken());
    }

    private User resolveLoginUser(SocialIdentityProvider provider, SocialOidcClient.FederatedIdentity claimed,
                                  SocialLoginTransaction transaction, Instant now) {
        var existingIdentity = identities.findByIssuerAndSubject(claimed.issuer(), claimed.subject());
        if (existingIdentity.isPresent()) {
            SocialIdentity identity = existingIdentity.get();
            User user = activeUserForUpdate(identity.getUserId());
            identity.markLogin(now);
            return user;
        }
        if (claimed.email() == null || claimed.email().isBlank() || !claimed.emailVerified()) {
            throw new InvalidSocialLoginException();
        }
        String email = EmailNormalizer.normalize(claimed.email());
        if (users.findByEmail(email).isPresent()) throw new SocialLinkRequiredException();
        if (!transaction.isTermsAccepted() || !transaction.isPrivacyAccepted()) throw new InvalidSocialLoginException();

        User user = new User(email, null, claimed.displayName(), true, true, null);
        user.setEmailConfirmed(true);
        try {
            user = users.saveAndFlush(user);
            identities.saveAndFlush(new SocialIdentity(user.getId(), user.getTenantId(), provider.getId(),
                    claimed.issuer(), claimed.subject(), email, true, now));
        } catch (DataIntegrityViolationException ex) {
            throw new SocialLinkRequiredException();
        }
        audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_IDENTITY_LINKED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, user,
                "social_only_account_created", java.util.Map.of("provider", provider.getProviderKey()));
        return user;
    }

    private void link(User user, SocialIdentityProvider provider, SocialOidcClient.FederatedIdentity claimed, Instant now) {
        var existing = identities.findByIssuerAndSubject(claimed.issuer(), claimed.subject());
        if (existing.isPresent()) {
            if (!existing.get().getUserId().equals(user.getId())) throw new InvalidSocialLoginException();
            return;
        }
        if (identities.existsByUserIdAndProviderId(user.getId(), provider.getId())) throw new InvalidSocialLoginException();
        identities.saveAndFlush(new SocialIdentity(user.getId(), user.getTenantId(), provider.getId(),
                claimed.issuer(), claimed.subject(), normalizedNullableEmail(claimed.email()),
                claimed.emailVerified(), now));
    }

    @Transactional(readOnly = true)
    public List<SocialIdentityResponse> list(UUID userId) {
        return identities.findByUserIdOrderByCreatedAtDesc(userId).stream().map(identity -> {
            String providerKey = providers.findById(identity.getProviderId()).map(SocialIdentityProvider::getProviderKey).orElse("disabled");
            return new SocialIdentityResponse(identity.getId(), providerKey, identity.getIssuer(),
                    identity.getEmailAtLink(), identity.getCreatedAt(), identity.getLastLoginAt());
        }).toList();
    }

    @Transactional
    public void unlink(UUID userId, UUID identityId, Jwt jwt, StepUpRequest request) {
        User user = activeUserForUpdate(userId);
        requireStrongStepUp(user, jwt, request, "social_unlink");
        SocialIdentity identity = identities.findByIdAndUserId(identityId, userId).orElseThrow(UserNotFoundException::new);
        long authenticators = (user.getPassword() == null ? 0 : 1)
                + passkeys.countByUserIdAndDisabledAtIsNull(userId)
                + identities.countByUserId(userId);
        if (authenticators <= 1) throw new LastAuthenticatorException();
        identities.delete(identity);
        identities.flush();
        tokenStorage.revokeAllSessions(userId.toString());
        audit.recordForAuthenticatedUser(SecurityEventType.SOCIAL_IDENTITY_UNLINKED,
                SecurityEventOutcome.SUCCESS, SecurityEventSeverity.HIGH, user,
                "social_identity_unlinked", java.util.Map.of("issuer", identity.getIssuer()));
    }

    private void requireStrongStepUp(User user, Jwt jwt, StepUpRequest request, String reason) {
        if (user.getPassword() != null) {
            stepUpService.verifyCurrentPassword(user, request == null ? null : request.currentPassword(),
                    SecurityEventType.ADMIN_ACTION, reason + "_password_step_up_failed");
            mfaService.requireMfaIfEnabled(user, request == null ? null : request.mfaCode(), reason);
            return;
        }
        List<String> amr = jwt.getClaimAsStringList("amr");
        Instant issuedAt = jwt.getIssuedAt();
        boolean freshWebauthn = amr != null && amr.contains("webauthn") && issuedAt != null
                && issuedAt.isAfter(Instant.now().minusSeconds(properties.getStepUp().getPasskeyFreshnessSeconds()));
        if (!freshWebauthn) throw new InvalidCredentialsException();
    }

    private User activeUserForUpdate(UUID id) {
        return users.findByIdForUpdate(id).filter(User::isActive).orElseThrow(UserNotFoundException::new);
    }
    private SocialIdentityProvider enabledProvider(String key) {
        SocialIdentityProvider provider = providers.findByProviderKey(key)
                .filter(SocialIdentityProvider::isEnabled).orElseThrow(InvalidSocialLoginException::new);
        requireAllowedIssuer(provider);
        return provider;
    }
    private void requireAllowedIssuer(SocialIdentityProvider provider) {
        Set<String> allowed = java.util.Arrays.stream(properties.getSocial().getIssuerAllowlist().split(","))
                .map(String::trim).filter(v -> !v.isBlank()).collect(java.util.stream.Collectors.toSet());
        if (!allowed.contains(provider.getIssuer())) throw new InvalidSocialLoginException();
        if (provider.getProviderType() == SocialProviderType.GOOGLE
                && !"https://accounts.google.com".equals(provider.getIssuer())) throw new InvalidSocialLoginException();
    }
    private void ensureEnabled() { if (!properties.getSocial().isEnabled()) throw new InvalidSocialLoginException(); }
    private String callbackUri(SocialIdentityProvider provider) {
        return properties.getSocial().getCallbackBaseUrl().replaceAll("/$", "")
                + "/api/v1/auth/social/" + provider.getProviderKey() + "/callback";
    }
    private String s256(String verifier) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }
    private String normalizedNullableEmail(String email) {
        return email == null || email.isBlank() ? null : EmailNormalizer.normalize(email);
    }

    public record CallbackResult(SocialCallbackResponse response, String refreshToken) {}
}
