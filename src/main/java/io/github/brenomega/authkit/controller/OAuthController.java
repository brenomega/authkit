package io.github.brenomega.authkit.controller;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
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
import io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.OAuthProviderService;
import jakarta.validation.Valid;

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
                Map.entry("authorization_endpoint", issuer + "/api/v1/oauth2/authorize"),
                Map.entry("token_endpoint", issuer + "/oauth2/token"),
                Map.entry("revocation_endpoint", issuer + "/oauth2/revoke"),
                Map.entry("introspection_endpoint", issuer + "/oauth2/introspect"),
                Map.entry("userinfo_endpoint", issuer + "/oauth2/userinfo"),
                Map.entry("jwks_uri", issuer + "/.well-known/jwks.json"),
                Map.entry("response_types_supported", List.of("code")),
                Map.entry("grant_types_supported", List.of("authorization_code")),
                Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")),
                Map.entry("revocation_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")),
                Map.entry("introspection_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post")),
                Map.entry("subject_types_supported", List.of("public")),
                Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
                Map.entry("code_challenge_methods_supported", List.of("S256")),
                Map.entry("scopes_supported", List.of("openid", "profile", "email")),
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

    @PostMapping(path = "/oauth2/token", consumes = "application/x-www-form-urlencoded")
    public OAuthTokenResponse token(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam("code_verifier") String codeVerifier) {
        ClientCredentials credentials = readClientCredentials(authorization, clientId, clientSecret);
        return oauthProviderService.token(
                grantType,
                code,
                redirectUri,
                credentials.clientId(),
                credentials.clientSecret(),
                codeVerifier);
    }

    @PostMapping(path = "/oauth2/revoke", consumes = "application/x-www-form-urlencoded")
    public void revoke(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        ClientCredentials credentials = readClientCredentials(authorization, clientId, clientSecret);
        oauthProviderService.revoke(token, tokenTypeHint, credentials.clientId(), credentials.clientSecret());
    }

    @PostMapping(path = "/oauth2/introspect", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> introspect(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("token") String token,
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
            throw new InvalidOAuthRequestException();
        }
        return oauthProviderService.userInfo(authorization.substring(7));
    }

    private ClientCredentials readClientCredentials(String authorization, String bodyClientId, String bodyClientSecret) {
        if (!StringUtils.hasText(authorization)) {
            if (!StringUtils.hasText(bodyClientId)) {
                throw new InvalidOAuthRequestException();
            }
            return new ClientCredentials(bodyClientId, bodyClientSecret);
        }
        if (!authorization.startsWith("Basic ")) {
            throw new InvalidOAuthRequestException();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 1) {
                throw new InvalidOAuthRequestException();
            }
            String basicClientId = decoded.substring(0, separator);
            String basicClientSecret = decoded.substring(separator + 1);
            if (StringUtils.hasText(bodyClientId) && !basicClientId.equals(bodyClientId)) {
                throw new InvalidOAuthRequestException();
            }
            return new ClientCredentials(basicClientId, basicClientSecret);
        } catch (IllegalArgumentException ex) {
            throw new InvalidOAuthRequestException();
        }
    }

    private record ClientCredentials(String clientId, String clientSecret) {
    }
}
