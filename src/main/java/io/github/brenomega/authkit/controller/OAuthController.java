package io.github.brenomega.authkit.controller;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeResponse;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizationDecisionRequest;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizationTransactionResponse;
import io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.OAuthProviderService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class OAuthController {

    private final OAuthProviderService oauthProviderService;
    private final AuthProperties authProperties;

    public OAuthController(OAuthProviderService oauthProviderService, AuthProperties authProperties) {
        this.oauthProviderService = oauthProviderService;
        this.authProperties = authProperties;
    }

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discovery() {
        String issuer = authProperties.getJwt().getIssuer();
        return Map.ofEntries(
                Map.entry("issuer", issuer),
                Map.entry("authorization_endpoint", issuer + "/oauth2/authorize"),
                Map.entry("token_endpoint", issuer + "/oauth2/token"),
                Map.entry("revocation_endpoint", issuer + "/oauth2/revoke"),
                Map.entry("introspection_endpoint", issuer + "/oauth2/introspect"),
                Map.entry("userinfo_endpoint", issuer + "/oauth2/userinfo"),
                Map.entry("jwks_uri", issuer + "/.well-known/jwks.json"),
                Map.entry("response_types_supported", List.of("code")),
                Map.entry("grant_types_supported", List.of("authorization_code", "refresh_token")),
                Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")),
                Map.entry("revocation_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")),
                Map.entry("introspection_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post")),
                Map.entry("subject_types_supported", List.of("public")),
                Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
                Map.entry("code_challenge_methods_supported", List.of("S256")),
                Map.entry("scopes_supported", List.of("openid", "profile", "email", "offline_access")),
                Map.entry("response_modes_supported", List.of("query")),
                Map.entry("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "email_verified", "tenant_id", "amr"))
        );
    }

    @PostMapping("/api/v1/oauth2/authorize")
    public ApiResponse<OAuthAuthorizeResponse> authorize(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody OAuthAuthorizeRequest request) {
        return new ApiResponse<>(oauthProviderService.authorize(jwt, request), null, Instant.now());
    }

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<Void> beginAuthorization(
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "nonce", required = false) String nonce) {
        String location = oauthProviderService.beginAuthorization(responseType, clientId, redirectUri, scope,
                state, codeChallenge, codeChallengeMethod, nonce);
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, location).build();
    }

    @GetMapping("/api/v1/oauth2/authorize/transactions/{transaction}")
    public ApiResponse<OAuthAuthorizationTransactionResponse> authorizationTransaction(
            @org.springframework.web.bind.annotation.PathVariable String transaction,
            @AuthenticationPrincipal Jwt jwt) {
        return new ApiResponse<>(oauthProviderService.authorizationTransaction(transaction, jwt), null, Instant.now());
    }

    @PostMapping("/api/v1/oauth2/authorize/transactions/{transaction}")
    public ResponseEntity<Void> resumeAuthorization(
            @org.springframework.web.bind.annotation.PathVariable String transaction,
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody OAuthAuthorizationDecisionRequest request) {
        String location = oauthProviderService.resumeAuthorization(transaction, jwt, request.approved());
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, location).build();
    }

    @PostMapping(path = "/oauth2/token", consumes = "application/x-www-form-urlencoded")
    public OAuthTokenResponse token(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        ClientCredentials credentials = readClientCredentials(authorization, clientId, clientSecret);
        return oauthProviderService.token(
                grantType,
                code,
                redirectUri,
                credentials.clientId(),
                credentials.clientSecret(),
                codeVerifier,
                refreshToken);
    }

    @PostMapping(path = "/oauth2/revoke", consumes = "application/x-www-form-urlencoded")
    public void revoke(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam(value = "token", required = false) String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        ClientCredentials credentials = readClientCredentials(authorization, clientId, clientSecret);
        oauthProviderService.revoke(token, tokenTypeHint, credentials.clientId(), credentials.clientSecret());
    }

    @PostMapping(path = "/oauth2/introspect", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> introspect(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam(value = "token", required = false) String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        ClientCredentials credentials = readClientCredentials(authorization, clientId, clientSecret);
        return oauthProviderService.introspect(token, tokenTypeHint, credentials.clientId(), credentials.clientSecret());
    }

    @GetMapping("/oauth2/userinfo")
    public Map<String, Object> userInfo(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (!StringUtils.hasText(authorization) || !authorization.startsWith("Bearer ")) {
            throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                    "invalid_token", "Bearer access token is required");
        }
        return oauthProviderService.userInfo(authorization.substring(7));
    }

    private ClientCredentials readClientCredentials(String authorization, String bodyClientId, String bodyClientSecret) {
        if (!StringUtils.hasText(authorization)) {
            if (!StringUtils.hasText(bodyClientId)) {
                throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                        "invalid_client", "Client authentication is required");
            }
            return new ClientCredentials(bodyClientId, bodyClientSecret);
        }
        if (!authorization.startsWith("Basic ")) {
            throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                    "invalid_client", "Unsupported client authentication method");
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 1) {
                throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                        "invalid_client", "Malformed client credentials");
            }
            String basicClientId = java.net.URLDecoder.decode(decoded.substring(0, separator), StandardCharsets.UTF_8);
            String basicClientSecret = java.net.URLDecoder.decode(decoded.substring(separator + 1), StandardCharsets.UTF_8);
            if (StringUtils.hasText(bodyClientId) && !basicClientId.equals(bodyClientId)) {
                throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                        "invalid_client", "Conflicting client credentials");
            }
            return new ClientCredentials(basicClientId, basicClientSecret);
        } catch (IllegalArgumentException ex) {
            throw new io.github.brenomega.authkit.exception.OAuthProtocolException(
                    "invalid_client", "Malformed client credentials");
        }
    }

    private record ClientCredentials(String clientId, String clientSecret) {
    }
}
