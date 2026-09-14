package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtTokenUseTest {

    @Test
    void tokenClassesAreExplicitAndMutuallyExclusive() {
        assertTrue(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "token_use", "first_party_access")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "token_use", "oauth_access", "client_id", "client", "scope", "openid")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "token_use", "id_token")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of("aud", List.of("api"))), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "client_id", "client", "scope", "openid")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "token_use", "first_party_access", "client_id", "client")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api"), "token_use", "first_party_access", "scope", "openid")), "api"));
        assertFalse(JwtTokenUse.isFirstPartyAccess(jwt(Map.of(
                "aud", List.of("api", "extra"), "token_use", "first_party_access")), "api"));
        assertTrue(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("client"), "token_use", "oauth_access", "client_id", "client", "scope", "openid"))));
        assertFalse(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("client"), "client_id", "client", "scope", "openid"))));
        assertFalse(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("client"), "token_use", "oauth_access", "client_id", "client"))));
        assertFalse(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("client", "extra"), "token_use", "oauth_access",
                "client_id", "client", "scope", "openid"))));
        assertFalse(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("other"), "token_use", "oauth_access",
                "client_id", "client", "scope", "openid"))));
        assertFalse(JwtTokenUse.isOAuthAccess(jwt(Map.of(
                "aud", List.of("client"), "token_use", "id_token"))));
        assertTrue(JwtTokenUse.isIdToken(jwt(Map.of(
                "aud", List.of("client"), "token_use", "id_token"))));
        assertFalse(JwtTokenUse.isIdToken(jwt(Map.of(
                "aud", List.of("client"), "token_use", "id_token", "scope", "openid"))));
        assertFalse(JwtTokenUse.isIdToken(jwt(Map.of(
                "aud", List.of("client", "extra"), "token_use", "id_token"))));
        assertFalse(JwtTokenUse.isIdToken(jwt(Map.of("aud", List.of("client")))));

        Map<String, Object> missingAmr = new HashMap<>();
        missingAmr.put("sub", UUID.randomUUID().toString());
        missingAmr.put("jti", UUID.randomUUID().toString());
        missingAmr.put("tenant_id", UUID.randomUUID().toString());
        missingAmr.put("aud", List.of("api"));
        missingAmr.put("token_use", "first_party_access");
        assertFalse(JwtTokenUse.isFirstPartyAccess(rawJwt(missingAmr), "api"));
    }

    private Jwt jwt(Map<String, Object> claims) {
        Map<String, Object> completeClaims = new HashMap<>(claims);
        completeClaims.putIfAbsent("sub", UUID.randomUUID().toString());
        completeClaims.putIfAbsent("jti", UUID.randomUUID().toString());
        completeClaims.putIfAbsent("tenant_id", UUID.randomUUID().toString());
        completeClaims.putIfAbsent("amr", List.of("pwd"));
        return rawJwt(completeClaims);
    }

    private Jwt rawJwt(Map<String, Object> claims) {
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("alg", "RS256"), claims);
    }
}
