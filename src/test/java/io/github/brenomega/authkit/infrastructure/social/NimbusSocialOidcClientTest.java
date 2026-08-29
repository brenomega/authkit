package io.github.brenomega.authkit.infrastructure.social;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.brenomega.authkit.exception.InvalidSocialLoginException;

class NimbusSocialOidcClientTest {

    @Test
    void acceptsOnlyExactClientAudienceAndMatchingOptionalAzp() {
        assertDoesNotThrow(() -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a"), null, "nonce"), "client-a", "nonce"));
        assertDoesNotThrow(() -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a"), "client-a", "nonce"), "client-a", "nonce"));

        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a", "client-b"), null, "nonce"), "client-a", "nonce"));
        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a", "client-b"), "client-a", "nonce"), "client-a", "nonce"));
        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a"), "client-b", "nonce"), "client-a", "nonce"));
        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-b"), "client-b", "nonce"), "client-a", "nonce"));
    }

    @Test
    void rejectsNonceAndSubjectSubstitution() {
        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                token(List.of("client-a"), null, "other"), "client-a", "nonce"));
        Jwt blankSubject = Jwt.withTokenValue("id-token")
                .header("alg", "RS256")
                .subject(" ")
                .audience(List.of("client-a"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("nonce", "nonce")
                .build();
        assertThrows(InvalidSocialLoginException.class, () -> NimbusSocialOidcClient.validateIdTokenClaims(
                blankSubject, "client-a", "nonce"));
    }

    private Jwt token(List<String> audience, String azp, String nonce) {
        Jwt.Builder builder = Jwt.withTokenValue("id-token")
                .header("alg", "RS256")
                .subject("subject")
                .audience(audience)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("nonce", nonce);
        if (azp != null) {
            builder.claim("azp", azp);
        }
        return builder.build();
    }
}
