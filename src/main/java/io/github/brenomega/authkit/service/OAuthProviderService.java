package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Optional;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeResponse;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizationTransactionResponse;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationCode;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationTransaction;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshToken;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshTokenFamily;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.OAuthProtocolException;
import io.github.brenomega.authkit.exception.OAuthRefreshReplayException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.JwtKeyService;
import io.github.brenomega.authkit.infrastructure.security.JwtTokenUse;
import io.github.brenomega.authkit.infrastructure.security.OAuthTokenRevocationService;
import io.github.brenomega.authkit.infrastructure.security.OAuthTransactionCodec;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.OAuthAuthorizationTransactionRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenFamilyRepository;
import io.github.brenomega.authkit.repository.OAuthRefreshTokenRepository;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Implements the authorization-code provider boundary for OAuth 2.0 and OpenID Connect.
 *
 * <p>The service binds authorization transactions and codes to the registered
 * client, exact redirect URI, approved scopes, resource owner, and PKCE S256
 * challenge. Only hashes of authorization transactions, codes, and refresh tokens
 * are persisted. Authorization transactions and codes are consumed through
 * conditional database updates so concurrent exchanges cannot both succeed.</p>
 *
 * <p>Refresh tokens form a database-locked rotation family. Every successful use
 * replaces the active token; presentation of a stale, expired, revoked, or
 * non-current family token revokes the entire family as suspected replay. The
 * replay exception is excluded from transaction rollback so that compromise state
 * and its critical audit evidence remain durable.</p>
 */
@Service
public class OAuthProviderService {

    private static final String PKCE_S256 = "S256";
    private static final Pattern PKCE_VERIFIER_PATTERN = Pattern.compile("[A-Za-z0-9._~-]{43,128}");
    private static final Pattern PKCE_CHALLENGE_PATTERN = Pattern.compile("[A-Za-z0-9_-]{43,128}");

    private final OAuthClientRepository clientRepository;
    private final OAuthAuthorizationCodeRepository authorizationCodeRepository;
    private final OAuthConsentRepository consentRepository;
    private final UserRepository userRepository;
    private final JwtEncoder jwtEncoder;
    private final AuthProperties authProperties;
    private final SecurityEventService securityEventService;
    private final PasswordEncoder passwordEncoder;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final AbuseThrottleService abuseThrottleService;
    private final OAuthTokenRevocationService tokenRevocationService;
    private final JwtDecoder oauthJwtDecoder;
    private final OAuthAuthorizationTransactionRepository authorizationTransactionRepository;
    private final OAuthRefreshTokenFamilyRepository refreshFamilyRepository;
    private final OAuthRefreshTokenRepository refreshTokenRepository;
    private final OAuthTransactionCodec transactionCodec;
    private final OAuthAccountTokenStateService accountTokenStateService;

    public OAuthProviderService(OAuthClientRepository clientRepository,
                                OAuthAuthorizationCodeRepository authorizationCodeRepository,
                                OAuthConsentRepository consentRepository,
                                UserRepository userRepository,
                                JwtEncoder jwtEncoder,
                                AuthProperties authProperties,
                                SecurityEventService securityEventService,
                                PasswordEncoder passwordEncoder,
                                Argon2ConcurrencyLimiter argon2Limiter,
                                AbuseThrottleService abuseThrottleService,
                                OAuthTokenRevocationService tokenRevocationService,
                                JwtKeyService jwtKeyService,
                                OAuthAuthorizationTransactionRepository authorizationTransactionRepository,
                                OAuthRefreshTokenFamilyRepository refreshFamilyRepository,
                                OAuthRefreshTokenRepository refreshTokenRepository,
                                OAuthTransactionCodec transactionCodec,
                                OAuthAccountTokenStateService accountTokenStateService) {
        this.clientRepository = clientRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.consentRepository = consentRepository;
        this.userRepository = userRepository;
        this.jwtEncoder = jwtEncoder;
        this.authProperties = authProperties;
        this.securityEventService = securityEventService;
        this.passwordEncoder = passwordEncoder;
        this.argon2Limiter = argon2Limiter;
        this.abuseThrottleService = abuseThrottleService;
        this.tokenRevocationService = tokenRevocationService;
        this.authorizationTransactionRepository = authorizationTransactionRepository;
        this.refreshFamilyRepository = refreshFamilyRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.transactionCodec = transactionCodec;
        this.accountTokenStateService = accountTokenStateService;
        this.oauthJwtDecoder = oauthJwtDecoder(jwtKeyService, tokenRevocationService, accountTokenStateService);
    }

    /**
     * Validates an authorization request and creates an expiring login transaction.
     * The returned value is a UI redirect containing the only raw transaction secret.
     */
    @Transactional
    public String beginAuthorization(String responseType, String clientId, String redirectUri, String scope,
                                     String state, String codeChallenge, String codeChallengeMethod, String nonce) {
        ensureEnabled();
        if (clientId == null || clientId.isBlank()) {
            throw new OAuthProtocolException("invalid_request", "client_id is required");
        }
        OAuthClient client = loadEnabledClient(clientId);
        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new OAuthProtocolException("invalid_request", "Invalid redirect_uri");
        }
        if (!"code".equals(responseType)) {
            return redirectWithError(
                redirectUri,
                "unsupported_response_type",
                "Only response_type=code is supported",
                state);
        }
        if (state == null || state.isBlank() || state.length() > 255) {
            return redirectWithError(redirectUri, "invalid_request", "state is required", null);
        }
        if (!PKCE_S256.equals(codeChallengeMethod) || codeChallenge == null
                || !PKCE_CHALLENGE_PATTERN.matcher(codeChallenge).matches()) {
            return redirectWithError(redirectUri, "invalid_request", "PKCE S256 is required", state);
        }
        Set<String> scopes = parseScopes(scope == null ? "" : scope);
        if (scopes.isEmpty() || !client.getScopes().containsAll(scopes)) {
            return redirectWithError(redirectUri, "invalid_scope", "Requested scope is not allowed", state);
        }
        if (scopes.contains("openid") && (nonce == null || nonce.isBlank() || nonce.length() > 255)) {
            return redirectWithError(redirectUri, "invalid_request", "nonce is required for OpenID Connect", state);
        }
        abuseThrottleService.checkClient(AbuseRateLimitPolicy.OAUTH_CLIENT, clientId);
        var issued = transactionCodec.issue();
        Instant now = Instant.now();
        authorizationTransactionRepository.save(new OAuthAuthorizationTransaction(
                issued.hash(), clientId, redirectUri, scopes, state, nonce, codeChallenge,
                codeChallengeMethod, now,
                now.plusSeconds(authProperties.getOauth().getAuthorizationCodeTtlMinutes() * 60)));
        return authProperties.getOauth().getAuthorizationUiUrl()
                + (authProperties.getOauth().getAuthorizationUiUrl().contains("?") ? "&" : "?")
                + "transaction=" + urlEncode(issued.raw());
    }

    /**
     * Resolves a live authorization transaction for the authenticated resource owner.
     * Consent is required when no active grant covers every requested scope.
     */
    @Transactional(readOnly = true)
    public OAuthAuthorizationTransactionResponse authorizationTransaction(String rawTransaction, Jwt principal) {
        OAuthAuthorizationTransaction transaction = loadAuthorizationTransaction(rawTransaction);
        OAuthClient client = loadEnabledClient(transaction.getClientId());
        User user = loadActiveUser(principal);
        OAuthConsent consent = consentRepository.findByUserIdAndClientIdAndRevokedAtIsNull(
                user.getId(), client.getClientId()).orElse(null);
        boolean consentRequired = consent == null || !consent.includes(transaction.getScopes());
        return new OAuthAuthorizationTransactionResponse(client.getClientId(), client.getDisplayName(),
                transaction.getScopes(), consentRequired,
                Math.max(0, transaction.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond()));
    }

    /**
     * Consumes an authorization transaction and returns its exact client redirect.
     * Consumption precedes either denial or code issuance, making the transaction single-use.
     */
    @Transactional
    public String resumeAuthorization(String rawTransaction, Jwt principal, boolean approved) {
        OAuthAuthorizationTransaction transaction = loadAuthorizationTransaction(rawTransaction);
        Instant now = Instant.now();
        if (authorizationTransactionRepository.consume(transaction.getId(), now) != 1) {
            throw new OAuthProtocolException("invalid_request", "Authorization transaction is expired or already used");
        }
        if (!approved) {
            return redirectWithError(
                    transaction.getRedirectUri(),
                    "access_denied",
                    "The resource owner denied the request",
                    transaction.getState());
        }
        OAuthClient client = loadEnabledClient(transaction.getClientId());
        User user = loadActiveUser(principal);
        ensureConsent(user, client, transaction.getScopes(), true);
        return issueAuthorizationCode(user, client, transaction.getRedirectUri(), transaction.getScopes(),
                principal.getClaimAsStringList("amr"), transaction.getCodeChallenge(),
                transaction.getCodeChallengeMethod(), transaction.getNonce(), transaction.getState());
    }

    private User loadActiveUser(Jwt principal) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(principal.getSubject()))
                .filter(User::isActive).orElseThrow(UserNotFoundException::new);
        user.requireEmailConfirmed();
        return user;
    }

    private OAuthAuthorizationTransaction loadAuthorizationTransaction(String raw) {
        String hash = transactionCodec.validatedHash(raw)
                .orElseThrow(() -> new OAuthProtocolException("invalid_request", "Invalid authorization transaction"));
        return authorizationTransactionRepository.findByTokenHash(hash)
                .filter(tx -> tx.getConsumedAt() == null)
                .filter(tx -> tx.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> new OAuthProtocolException(
                    "invalid_request",
                    "Authorization transaction is expired or already used"));
    }

    /**
     * Issues a hashed, expiring authorization code after client, consent, and PKCE validation.
     * The raw code appears only in the returned client redirect.
     */
    @Transactional
    public OAuthAuthorizeResponse authorize(Jwt principal, OAuthAuthorizeRequest request) {
        ensureEnabled();
        if (!"code".equals(request.responseType())) {
            throw new InvalidOAuthRequestException();
        }
        abuseThrottleService.checkClient(AbuseRateLimitPolicy.OAUTH_CLIENT, request.clientId());
        OAuthClient client = loadEnabledClient(request.clientId());
        if (!client.getRedirectUris().contains(request.redirectUri())) {
            throw new InvalidOAuthRequestException();
        }
        if (!PKCE_S256.equals(request.codeChallengeMethod())) {
            throw new InvalidOAuthRequestException();
        }
        if (!PKCE_CHALLENGE_PATTERN.matcher(request.codeChallenge()).matches()) {
            throw new InvalidOAuthRequestException();
        }

        Set<String> requestedScopes = parseScopes(request.scope());
        if (requestedScopes.isEmpty() || !client.getScopes().containsAll(requestedScopes)) {
            throw new InvalidOAuthRequestException();
        }

        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(principal.getSubject()))
                .filter(User::isActive)
                .orElseThrow(UserNotFoundException::new);
        user.requireEmailConfirmed();
        ensureConsent(user, client, requestedScopes, request.consentAccepted());

        String rawCode = SecureTokenGenerator.randomUrlSafeToken(32);
        Instant now = Instant.now();
        OAuthAuthorizationCode code = authorizationCodeRepository.save(new OAuthAuthorizationCode(
                TokenHasher.sha256Hex(rawCode),
                client.getClientId(),
                user.getId(),
                user.getTenantId(),
                request.redirectUri(),
                requestedScopes,
                principal.getClaimAsStringList("amr") == null
                        ? Set.of("pwd")
                        : new LinkedHashSet<>(principal.getClaimAsStringList("amr")),
                request.codeChallenge(),
                request.codeChallengeMethod(),
                request.nonce(),
                now,
                now.plusSeconds(authProperties.getOauth().getAuthorizationCodeTtlMinutes() * 60)));

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_AUTHORIZATION_CODE_ISSUED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "oauth_authorization_code_issued",
                Map.of("client_id", client.getClientId()));

        return new OAuthAuthorizeResponse(
                redirectWithCode(code.getRedirectUri(), rawCode, request.state()),
                request.state(),
                authProperties.getOauth().getAuthorizationCodeTtlMinutes() * 60);
    }

    @Transactional
    public OAuthTokenResponse token(String grantType,
                                    String code,
                                    String redirectUri,
                                    String clientId,
                                    String clientSecret,
                                    String codeVerifier) {
        return token(grantType, code, redirectUri, clientId, clientSecret, codeVerifier, null);
    }

    /**
     * Exchanges an authorization code or rotates a refresh token for an authenticated client.
     *
     * <p>Authorization codes are consumed atomically and remain bound to the exact
     * redirect URI and PKCE verifier. Refresh rotation locks both token and family;
     * detected reuse commits family-wide revocation before reporting failure.</p>
     *
     * @throws OAuthRefreshReplayException when a refresh family is treated as compromised
     */
    @Transactional(noRollbackFor = OAuthRefreshReplayException.class)
    public OAuthTokenResponse token(String grantType,
                                    String code,
                                    String redirectUri,
                                    String clientId,
                                    String clientSecret,
                                    String codeVerifier,
                                    String refreshToken) {
        ensureEnabled();
        if (clientId == null || clientId.isBlank()) {
            throw new OAuthProtocolException("invalid_client", "Client authentication is required");
        }
        abuseThrottleService.checkClient(AbuseRateLimitPolicy.OAUTH_CLIENT, clientId);
        OAuthClient client = loadEnabledClient(clientId);
        validateClientAuthentication(client, clientSecret);
        if ("authorization_code".equals(grantType)) {
            return exchangeAuthorizationCode(code, redirectUri, codeVerifier, client);
        }
        if ("refresh_token".equals(grantType)) {
            return rotateRefreshToken(refreshToken, client);
        }
        throw new OAuthProtocolException(
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported");
    }

    private OAuthTokenResponse exchangeAuthorizationCode(String code,
                                                          String redirectUri,
                                                          String codeVerifier,
                                                          OAuthClient client) {
        if (code == null || code.isBlank()
                || redirectUri == null || redirectUri.isBlank()
                || codeVerifier == null || !PKCE_VERIFIER_PATTERN.matcher(codeVerifier).matches()) {
            throw new OAuthProtocolException(
                "invalid_request",
                "code, redirect_uri and a valid code_verifier are required");
        }

        String codeHash = TokenHasher.sha256Hex(code);
        OAuthAuthorizationCode authorizationCode = authorizationCodeRepository.findByCodeHash(codeHash)
                .filter(existing -> existing.getConsumedAt() == null)
                .filter(existing -> existing.getExpiresAt().isAfter(Instant.now()))
                .filter(existing -> existing.getClientId().equals(client.getClientId()))
                .filter(existing -> existing.getRedirectUri().equals(redirectUri))
                .orElseThrow(() -> new OAuthProtocolException(
                    "invalid_grant",
                    "Authorization code is invalid, expired or already used"));

        if (client.isRequirePkce() && !pkceMatches(codeVerifier, authorizationCode.getCodeChallenge())) {
            throw new OAuthProtocolException("invalid_grant", "PKCE verification failed");
        }

        if (authorizationCodeRepository.consume(codeHash, Instant.now()) != 1) {
            throw new OAuthProtocolException("invalid_grant", "Authorization code is invalid, expired or already used");
        }

        @SuppressWarnings("null")
        User user = userRepository.findByIdForUpdate(authorizationCode.getUserId())
                .filter(User::isActive)
                .orElseThrow(InvalidOAuthRequestException::new);
        user.requireEmailConfirmed();

        IssuedRefreshToken issuedRefresh = authorizationCode.getScopes().contains("offline_access")
                ? issueRefreshTokenFamily(user, client, authorizationCode.getScopes(), authorizationCode.getAmr())
                : null;
        String accessToken = issueAccessToken(user, client, authorizationCode.getScopes(), authorizationCode.getAmr(),
                issuedRefresh == null ? null : issuedRefresh.familyId());
        String idToken = authorizationCode.getScopes().contains("openid")
                ? issueIdToken(user, client, authorizationCode)
                : null;

        securityEventService.recordForTargetUser(
                SecurityEventType.OAUTH_TOKEN_ISSUED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "oauth_token_issued",
                Map.of("client_id", client.getClientId()));

        return new OAuthTokenResponse(
                accessToken,
                idToken,
                issuedRefresh == null ? null : issuedRefresh.rawToken(),
                "Bearer",
                authProperties.getToken().getAccessTokenTtlSeconds(),
                String.join(" ", authorizationCode.getScopes()));
    }

    @SuppressWarnings("null")
    private OAuthTokenResponse rotateRefreshToken(String rawRefreshToken, OAuthClient client) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank() || rawRefreshToken.length() > 512) {
            throw new OAuthProtocolException("invalid_request", "refresh_token is required");
        }
        Instant now = Instant.now();
        String tokenHash = TokenHasher.sha256Hex(rawRefreshToken);
        UUID resourceOwnerId = refreshTokenRepository.findUserIdByTokenHash(tokenHash)
                .orElseThrow(() -> new OAuthProtocolException("invalid_grant", "Refresh token is invalid"));
        User user = userRepository.findByIdForUpdate(resourceOwnerId)
                .filter(User::isActive)
                .orElseThrow(() -> new OAuthProtocolException("invalid_grant", "Resource owner is not active"));
        user.requireEmailConfirmed();
        OAuthRefreshToken token = refreshTokenRepository.findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() -> new OAuthProtocolException("invalid_grant", "Refresh token is invalid"));
        OAuthRefreshTokenFamily family = refreshFamilyRepository.findByIdForUpdate(token.getFamilyId())
                .orElseThrow(() -> new OAuthProtocolException("invalid_grant", "Refresh token family is invalid"));
        if (!family.getClientId().equals(client.getClientId())) {
            throw new OAuthProtocolException("invalid_grant", "Refresh token does not belong to this client");
        }
        if (!token.isActive(now) || !family.isActive(now)
                || !MessageDigest.isEqual(tokenHash.getBytes(StandardCharsets.US_ASCII),
                        family.getActiveTokenHash().getBytes(StandardCharsets.US_ASCII))
                || !accountTokenStateService.isRefreshFamilyLive(family.getUserId(), family.getCreatedAt())) {
            family.revoke(now, true);
            refreshTokenRepository.findByFamilyId(family.getId()).forEach(existing -> existing.revoke(now));
            userRepository.findById(family.getUserId()).ifPresent(replayUser -> securityEventService.recordForTargetUser(
                    SecurityEventType.REFRESH_TOKEN_REUSE_DETECTED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.CRITICAL,
                    replayUser,
                    "oauth_refresh_token_reuse_detected",
                    Map.of("client_id", client.getClientId(), "family_id", family.getId().toString())));
            refreshTokenRepository.flush();
            refreshFamilyRepository.flush();
            throw new OAuthRefreshReplayException();
        }
        String replacement = SecureTokenGenerator.randomUrlSafeToken(48);
        String replacementHash = TokenHasher.sha256Hex(replacement);
        token.consume(now, replacementHash);
        family.rotate(replacementHash);
        refreshTokenRepository.save(new OAuthRefreshToken(replacementHash, family.getId(), now, family.getExpiresAt()));

        String accessToken = issueAccessToken(user, client, family.getScopes(), family.getAmr(), family.getId());
        securityEventService.recordForTargetUser(
                SecurityEventType.OAUTH_TOKEN_ISSUED, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.MEDIUM,
                user, "oauth_refresh_token_rotated", Map.of("client_id", client.getClientId()));
        return new OAuthTokenResponse(accessToken, null, replacement, "Bearer",
                authProperties.getToken().getAccessTokenTtlSeconds(), String.join(" ", family.getScopes()));
    }

    private IssuedRefreshToken issueRefreshTokenFamily(
        User user,
        OAuthClient client,
        Set<String> scopes,
        Set<String> amr) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(authProperties.getOauth().getRefreshTokenTtlDays() * 86_400);
        String raw = SecureTokenGenerator.randomUrlSafeToken(48);
        String hash = TokenHasher.sha256Hex(raw);
        UUID familyId = UUID.randomUUID();
        refreshFamilyRepository.save(new OAuthRefreshTokenFamily(
                familyId, user.getId(), client.getClientId(), scopes, amr, hash, now, expiresAt));
        refreshTokenRepository.save(new OAuthRefreshToken(hash, familyId, now, expiresAt));
        return new IssuedRefreshToken(raw, familyId);
    }

    /**
     * Revokes a client-owned refresh family or OAuth access-token JTI.
     * Unknown, malformed, mismatched, and previously revoked token values do not disclose validity.
     */
    @Transactional
    public void revoke(String token, String tokenTypeHint, String clientId, String clientSecret) {
        ensureEnabled();
        if (token == null || token.isBlank()) {
            throw new OAuthProtocolException("invalid_request", "token is required");
        }
        OAuthClient client = loadEnabledClient(clientId);
        abuseThrottleService.checkClient(AbuseRateLimitPolicy.OAUTH_CLIENT, client.getClientId());
        validateClientAuthentication(client, clientSecret);
        Instant now = Instant.now();
        refreshTokenRepository.findByTokenHashForUpdate(TokenHasher.sha256Hex(token)).ifPresent(refresh -> {
            refreshFamilyRepository.findByIdForUpdate(refresh.getFamilyId())
                    .filter(family -> family.getClientId().equals(client.getClientId()))
                    .ifPresent(family -> {
                        family.revoke(now, false);
                        refreshTokenRepository.findByFamilyId(family.getId()).forEach(existing -> existing.revoke(now));
                    });
        });
        decodeOAuthToken(token)
                .filter(JwtTokenUse::isOAuthAccess)
                .filter(jwt -> jwt.getAudience().contains(client.getClientId()))
                .ifPresent(jwt -> tokenRevocationService.revoke(jwt.getId(), jwt.getExpiresAt()));
    }

    /**
     * Returns active metadata only when the authenticated client owns the token audience or family.
     * All invalid, expired, revoked, replayed, and client-mismatched values collapse to inactive.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> introspect(String token, String tokenTypeHint, String clientId, String clientSecret) {
        ensureEnabled();
        if (token == null || token.isBlank()) {
            throw new OAuthProtocolException("invalid_request", "token is required");
        }
        OAuthClient client = loadEnabledClient(clientId);
        abuseThrottleService.checkClient(AbuseRateLimitPolicy.OAUTH_CLIENT, client.getClientId());
        validateIntrospectionClient(client, clientSecret);
        String refreshHash = TokenHasher.sha256Hex(token);
        var refresh = refreshTokenRepository.findByTokenHash(refreshHash).orElse(null);
        if (refresh != null) {
            Optional<OAuthRefreshTokenFamily> family = refreshFamilyRepository.findById(refresh.getFamilyId());
            if (family.isPresent()) {
                OAuthRefreshTokenFamily activeFamily = family.get();
                if (activeFamily.getClientId().equals(client.getClientId())
                        && refresh.isActive(Instant.now()) && activeFamily.isActive(Instant.now())
                        && accountTokenStateService.isRefreshFamilyLive(
                                activeFamily.getUserId(), activeFamily.getCreatedAt())
                        && MessageDigest.isEqual(refreshHash.getBytes(StandardCharsets.US_ASCII),
                                activeFamily.getActiveTokenHash().getBytes(StandardCharsets.US_ASCII))) {
                    return Map.of("active", true, "client_id", activeFamily.getClientId(),
                            "sub", activeFamily.getUserId().toString(),
                            "scope", String.join(" ", activeFamily.getScopes()),
                            "token_type", "refresh_token",
                            "exp", activeFamily.getExpiresAt().getEpochSecond());
                }
            }
            return Map.of("active", false);
        }
        return decodeOAuthToken(token)
                .filter(JwtTokenUse::isOAuthAccess)
                .filter(jwt -> jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now()))
                .filter(jwt -> jwt.getAudience().contains(client.getClientId()))
                .map(jwt -> Map.<String, Object>ofEntries(
                        Map.entry("active", true),
                        Map.entry("sub", jwt.getSubject()),
                        Map.entry("client_id", jwt.getClaimAsString("client_id") == null
                                ? client.getClientId()
                                : jwt.getClaimAsString("client_id")),
                        Map.entry("scope", jwt.getClaimAsString("scope") == null ? "" : jwt.getClaimAsString("scope")),
                        Map.entry("token_type", "Bearer"),
                        Map.entry("iss", jwt.getClaimAsString("iss") == null
                                ? authProperties.getJwt().getIssuer()
                                : jwt.getClaimAsString("iss")),
                        Map.entry("aud", jwt.getAudience()),
                        Map.entry("iat", jwt.getIssuedAt() == null ? 0L : jwt.getIssuedAt().getEpochSecond()),
                        Map.entry("exp", jwt.getExpiresAt().getEpochSecond()),
                        Map.entry("jti", jwt.getId())))
                .orElse(Map.of("active", false));
    }

    /**
     * Resolves current account claims authorized by a live OAuth access token.
     * Email and profile claims are included only when their corresponding scopes are present.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> userInfo(String bearerToken) {
        ensureEnabled();
        Jwt jwt = decodeOAuthToken(bearerToken)
                .filter(JwtTokenUse::isOAuthAccess)
                .filter(token -> hasScope(token, "openid"))
                .orElseThrow(() -> new OAuthProtocolException(
                    "invalid_token",
                    "A live OAuth access token with openid scope is required"));
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(jwt.getSubject()))
                .filter(User::isActive)
                .orElseThrow(InvalidOAuthRequestException::new);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.getId().toString());
        claims.put("tenant_id", user.getTenantId().toString());
        if (hasScope(jwt, "email")) {
            claims.put("email", user.getEmail());
            claims.put("email_verified", user.isEmailConfirmed());
        }
        if (hasScope(jwt, "profile") && user.getName() != null && !user.getName().isBlank()) {
            claims.put("name", user.getName());
        }
        return claims;
    }

    @SuppressWarnings("null")
    private OAuthClient loadEnabledClient(String clientId) {
        return clientRepository.findByClientId(clientId)
                .filter(OAuthClient::isEnabled)
                .orElseThrow(() -> new OAuthProtocolException("invalid_client", "Unknown or disabled OAuth client"));
    }

    private void ensureConsent(User user, OAuthClient client, Set<String> requestedScopes, Boolean consentAccepted) {
        OAuthConsent existingConsent = consentRepository
                .findByUserIdAndClientIdAndRevokedAtIsNull(user.getId(), client.getClientId())
                .orElse(null);
        if (existingConsent != null && existingConsent.includes(requestedScopes)) {
            return;
        }
        if (!Boolean.TRUE.equals(consentAccepted)) {
            throw new InvalidOAuthRequestException();
        }

        Instant now = Instant.now();
        OAuthConsent consent = existingConsent == null
                ? new OAuthConsent(user.getId(), user.getTenantId(), client.getClientId(), requestedScopes, now)
                : existingConsent;
        if (existingConsent != null) {
            consent.grant(requestedScopes, now);
        }
        consentRepository.save(consent);

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_CONSENT_GRANTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "oauth_consent_granted",
                Map.of("client_id", client.getClientId(), "scopes", String.join(" ", requestedScopes)));
    }

    private void validateClientAuthentication(OAuthClient client, String clientSecret) {
        if (client.isPublicClient()) {
            return;
        }
        if (clientSecret == null || clientSecret.isBlank() || clientSecret.length() > 256) {
            throw new InvalidOAuthRequestException();
        }
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }
        try {
            if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
                throw new InvalidOAuthRequestException();
            }
        } finally {
            argon2Limiter.release();
        }
    }

    private void validateIntrospectionClient(OAuthClient client, String clientSecret) {
        if (client.isPublicClient()) {
            throw new OAuthProtocolException("invalid_client", "Introspection requires a confidential client");
        }
        validateClientAuthentication(client, clientSecret);
    }

    private boolean pkceMatches(String verifier, String expectedChallenge) {
        String actualChallenge = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(sha256(verifier));
        return MessageDigest.isEqual(
                expectedChallenge.getBytes(StandardCharsets.UTF_8),
                actualChallenge.getBytes(StandardCharsets.UTF_8));
    }

    private Optional<Jwt> decodeOAuthToken(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(oauthJwtDecoder.decode(token));
        } catch (JwtException ex) {
            return Optional.empty();
        }
    }

    private boolean hasScope(Jwt jwt, String scope) {
        String scopes = jwt.getClaimAsString("scope");
        return scopes != null && Arrays.asList(scopes.split("\\s+")).contains(scope);
    }

    private JwtDecoder oauthJwtDecoder(JwtKeyService jwtKeyService,
                                       OAuthTokenRevocationService tokenRevocationService,
                                       OAuthAccountTokenStateService accountTokenStateService) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(jwtKeyService.publishedPublicJwkSet()));
        jwtProcessor.setJWSKeySelector(keySelector);
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);
        OAuth2TokenValidator<Jwt> defaultValidator =
                JwtValidators.createDefaultWithIssuer(authProperties.getJwt().getIssuer());
        OAuth2TokenValidator<Jwt> keyRevocationValidator = jwt -> {
            Object kid = jwt.getHeaders().get("kid");
            if (!(kid instanceof String keyId) || keyId.isBlank() || !jwtKeyService.isPublishedKid(keyId)) {
                return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                        new org.springframework.security.oauth2.core.OAuth2Error(
                            "invalid_token", "JWT signing key ID is missing or not published",
                            null));
            }
            return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success();
        };
        OAuth2TokenValidator<Jwt> tokenRevocationValidator = jwt -> {
            if (tokenRevocationService.isRevoked(jwt.getId())) {
                return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                        new org.springframework.security.oauth2.core.OAuth2Error(
                            "invalid_token",
                            "JWT has been revoked",
                            null));
            }
            return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success();
        };
        OAuth2TokenValidator<Jwt> accountStateValidator = jwt -> {
            if (!accountTokenStateService.isAccessTokenLive(jwt)) {
                return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                        new org.springframework.security.oauth2.core.OAuth2Error(
                                "invalid_token", "Resource owner or token epoch is not active", null));
            }
            return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success();
        };
        @SuppressWarnings("null")
        OAuth2TokenValidator<Jwt> refreshFamilyValidator = jwt -> {
            String familyClaim = jwt.getClaimAsString("refresh_family_id");
            if (familyClaim == null) {
                return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success();
            }
            try {
                return refreshFamilyRepository.findById(UUID.fromString(familyClaim))
                        .filter(family -> family.isActive(Instant.now()))
                        .map(family -> org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success())
                        .orElseGet(() -> org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                                new org.springframework.security.oauth2.core.OAuth2Error(
                                        "invalid_token", "Refresh token family has been revoked", null)));
            } catch (IllegalArgumentException ex) {
                return org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                        new org.springframework.security.oauth2.core.OAuth2Error(
                                "invalid_token", "Invalid refresh token family", null));
            }
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                defaultValidator,
                jwt -> JwtTokenUse.isOAuthAccess(jwt)
                        ? org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success()
                        : org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.failure(
                                new org.springframework.security.oauth2.core.OAuth2Error(
                                        "invalid_token", "Token is not an OAuth access token", null)),
                keyRevocationValidator,
                tokenRevocationValidator,
                refreshFamilyValidator,
                accountStateValidator));
        return decoder;
    }

    private String issueAccessToken(User user, OAuthClient client, Set<String> scopes, Set<String> amr,
                                    UUID refreshFamilyId) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(List.of(client.getClientId()))
                .subject(user.getId().toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(authProperties.getToken().getAccessTokenTtlSeconds()))
                .claim("tenant_id", user.getTenantId().toString())
                .claim(JwtTokenUse.CLAIM, JwtTokenUse.OAUTH_ACCESS)
                .claim("client_id", client.getClientId())
                .claim(OAuthAccountTokenStateService.EPOCH_CLAIM,
                        accountTokenStateService.currentEpoch(user.getId()))
                .claim("scope", String.join(" ", scopes))
                .claim("amr", List.copyOf(amr));
        if (refreshFamilyId != null) {
            claims.claim("refresh_family_id", refreshFamilyId.toString());
        }
        return encode(claims.build());
    }

    private String issueIdToken(User user, OAuthClient client, OAuthAuthorizationCode code) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(List.of(client.getClientId()))
                .subject(user.getId().toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(authProperties.getOauth().getIdTokenTtlSeconds()))
                .claim("tenant_id", user.getTenantId().toString())
                .claim(JwtTokenUse.CLAIM, JwtTokenUse.ID_TOKEN)
                .claim("amr", List.copyOf(code.getAmr()));
        if (code.getNonce() != null && !code.getNonce().isBlank()) {
            claims.claim("nonce", code.getNonce());
        }
        if (code.getScopes().contains("email")) {
            claims.claim("email", user.getEmail())
                    .claim("email_verified", user.isEmailConfirmed());
        }
        if (code.getScopes().contains("profile") && user.getName() != null && !user.getName().isBlank()) {
            claims.claim("name", user.getName());
        }
        return encode(claims.build());
    }

    private String encode(JwtClaimsSet claims) {
        JwsHeader headers = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(authProperties.getJwt().getKeyId())
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(headers, claims)).getTokenValue();
    }

    private String redirectWithCode(String redirectUri, String code, String state) {
        String separator = redirectUri.contains("?") ? "&" : "?";
        String result = redirectUri + separator + "code=" + urlEncode(code);
        if (state != null && !state.isBlank()) {
            result += "&state=" + urlEncode(state);
        }
        return result;
    }

    private String redirectWithError(String redirectUri, String error, String description, String state) {
        String separator = redirectUri.contains("?") ? "&" : "?";
        String result = redirectUri + separator + "error=" + urlEncode(error)
                + "&error_description=" + urlEncode(description);
        if (state != null && !state.isBlank()) {
            result += "&state=" + urlEncode(state);
        }
        return result;
    }

    private String issueAuthorizationCode(User user, OAuthClient client, String redirectUri, Set<String> scopes,
                                          List<String> principalAmr, String challenge, String challengeMethod,
                                          String nonce, String state) {
        String rawCode = SecureTokenGenerator.randomUrlSafeToken(32);
        Instant now = Instant.now();
        Set<String> amr = principalAmr == null || principalAmr.isEmpty()
                ? Set.of("pwd") : new LinkedHashSet<>(principalAmr);
        OAuthAuthorizationCode code = authorizationCodeRepository.save(new OAuthAuthorizationCode(
                TokenHasher.sha256Hex(rawCode), client.getClientId(), user.getId(), user.getTenantId(),
                redirectUri, scopes, amr, challenge, challengeMethod, nonce, now,
                now.plusSeconds(authProperties.getOauth().getAuthorizationCodeTtlMinutes() * 60)));
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.OAUTH_AUTHORIZATION_CODE_ISSUED, SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM, user, "oauth_authorization_code_issued",
                Map.of("client_id", client.getClientId()));
        return redirectWithCode(code.getRedirectUri(), rawCode, state);
    }

    @SuppressWarnings("null")
    private Set<String> parseScopes(String scope) {
        return Arrays.stream(scope.split("\\s+"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void ensureEnabled() {
        if (!authProperties.getOauth().isProviderEnabled()) {
            throw new InvalidOAuthRequestException();
        }
    }

    private record IssuedRefreshToken(String rawToken, UUID familyId) {
    }
}
