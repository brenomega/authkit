package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationCode;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent;
import io.github.brenomega.authkit.domain.user.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.user.dto.OAuthAuthorizeResponse;
import io.github.brenomega.authkit.domain.user.dto.OAuthTokenResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@Service
public class OAuthProviderService {

    private static final String PKCE_S256 = "S256";

    private final OAuthClientRepository clientRepository;
    private final OAuthAuthorizationCodeRepository authorizationCodeRepository;
    private final OAuthConsentRepository consentRepository;
    private final UserRepository userRepository;
    private final JwtEncoder jwtEncoder;
    private final AuthProperties authProperties;
    private final SecurityEventService securityEventService;

    public OAuthProviderService(OAuthClientRepository clientRepository,
                                OAuthAuthorizationCodeRepository authorizationCodeRepository,
                                OAuthConsentRepository consentRepository,
                                UserRepository userRepository,
                                JwtEncoder jwtEncoder,
                                AuthProperties authProperties,
                                SecurityEventService securityEventService) {
        this.clientRepository = clientRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.consentRepository = consentRepository;
        this.userRepository = userRepository;
        this.jwtEncoder = jwtEncoder;
        this.authProperties = authProperties;
        this.securityEventService = securityEventService;
    }

    @Transactional
    public OAuthAuthorizeResponse authorize(Jwt principal, OAuthAuthorizeRequest request) {
        ensureEnabled();
        if (!"code".equals(request.responseType())) {
            throw new InvalidOAuthRequestException();
        }
        OAuthClient client = loadEnabledClient(request.clientId());
        if (!client.getRedirectUris().contains(request.redirectUri())) {
            throw new InvalidOAuthRequestException();
        }
        if (!PKCE_S256.equals(request.codeChallengeMethod())) {
            throw new InvalidOAuthRequestException();
        }

        Set<String> requestedScopes = parseScopes(request.scope());
        if (requestedScopes.isEmpty() || !client.getScopes().containsAll(requestedScopes)) {
            throw new InvalidOAuthRequestException();
        }

        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(principal.getSubject()))
                .filter(existing -> !existing.isDeleted())
                .orElseThrow(UserNotFoundException::new);
        user.requireEmailConfirmed();
        requireTenantAccess(user, client);
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
                java.util.Map.of("client_id", client.getClientId()));

        return new OAuthAuthorizeResponse(
                redirectWithCode(code.getRedirectUri(), rawCode, request.state()),
                rawCode,
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
        ensureEnabled();
        if (!"authorization_code".equals(grantType)
                || code == null || code.isBlank()
                || redirectUri == null || redirectUri.isBlank()
                || clientId == null || clientId.isBlank()
                || codeVerifier == null || codeVerifier.isBlank()) {
            throw new InvalidOAuthRequestException();
        }

        OAuthClient client = loadEnabledClient(clientId);
        validateClientAuthentication(client, clientSecret);

        String codeHash = TokenHasher.sha256Hex(code);
        OAuthAuthorizationCode authorizationCode = authorizationCodeRepository.findByCodeHash(codeHash)
                .filter(existing -> existing.getConsumedAt() == null)
                .filter(existing -> existing.getExpiresAt().isAfter(Instant.now()))
                .filter(existing -> existing.getClientId().equals(client.getClientId()))
                .filter(existing -> existing.getRedirectUri().equals(redirectUri))
                .orElseThrow(InvalidOAuthRequestException::new);

        if (client.isRequirePkce() && !pkceMatches(codeVerifier, authorizationCode.getCodeChallenge())) {
            throw new InvalidOAuthRequestException();
        }

        if (authorizationCodeRepository.consume(codeHash, Instant.now()) != 1) {
            throw new InvalidOAuthRequestException();
        }

        @SuppressWarnings("null")
        User user = userRepository.findById(authorizationCode.getUserId())
                .filter(existing -> !existing.isDeleted())
                .orElseThrow(InvalidOAuthRequestException::new);
        user.requireEmailConfirmed();

        String accessToken = issueAccessToken(user, client, authorizationCode.getScopes(), authorizationCode.getAmr());
        String idToken = authorizationCode.getScopes().contains("openid")
                ? issueIdToken(user, client, authorizationCode)
                : null;

        securityEventService.recordForTargetUser(
                SecurityEventType.OAUTH_TOKEN_ISSUED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "oauth_token_issued",
                java.util.Map.of("client_id", client.getClientId()));

        return new OAuthTokenResponse(
                accessToken,
                idToken,
                "Bearer",
                authProperties.getToken().getAccessTokenTtlSeconds(),
                String.join(" ", authorizationCode.getScopes()));
    }

    private OAuthClient loadEnabledClient(String clientId) {
        return clientRepository.findByClientId(clientId)
                .filter(OAuthClient::isEnabled)
                .orElseThrow(InvalidOAuthRequestException::new);
    }

    private void requireTenantAccess(User user, OAuthClient client) {
        if (client.getTenantId() != null && !client.getTenantId().equals(user.getTenantId())) {
            throw new InvalidOAuthRequestException();
        }
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
                java.util.Map.of("client_id", client.getClientId(), "scopes", String.join(" ", requestedScopes)));
    }

    private void validateClientAuthentication(OAuthClient client, String clientSecret) {
        if (client.isPublicClient()) {
            return;
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new InvalidOAuthRequestException();
        }
        byte[] expected = client.getClientSecretHash().getBytes(StandardCharsets.UTF_8);
        byte[] actual = TokenHasher.sha256Hex(clientSecret).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidOAuthRequestException();
        }
    }

    private boolean pkceMatches(String verifier, String expectedChallenge) {
        String actualChallenge = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(sha256(verifier));
        return MessageDigest.isEqual(
                expectedChallenge.getBytes(StandardCharsets.UTF_8),
                actualChallenge.getBytes(StandardCharsets.UTF_8));
    }

    private String issueAccessToken(User user, OAuthClient client, Set<String> scopes, Set<String> amr) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(List.of(client.getClientId()))
                .subject(user.getId().toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(authProperties.getToken().getAccessTokenTtlSeconds()))
                .claim("tenant_id", user.getTenantId().toString())
                .claim("client_id", client.getClientId())
                .claim("scope", String.join(" ", scopes))
                .claim("amr", List.copyOf(amr))
                .build();
        return encode(claims);
    }

    private String issueIdToken(User user, OAuthClient client, OAuthAuthorizationCode code) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(List.of(client.getClientId()))
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(authProperties.getOauth().getIdTokenTtlSeconds()))
                .claim("tenant_id", user.getTenantId().toString())
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

    private Set<String> parseScopes(String scope) {
        return Arrays.stream(scope.split("\\s+"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.NoSuchAlgorithmException ex) {
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
}
