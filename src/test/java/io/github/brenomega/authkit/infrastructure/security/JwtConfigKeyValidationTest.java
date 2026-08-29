package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.brenomega.authkit.util.RsaKeyGenerator;

class JwtConfigKeyValidationTest {

    @Test
    void rejectsMissingUnknownAndRevokedKidAndAcceptsPublishedKid() {
        var pair = RsaKeyGenerator.generateKeyPair();
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setKeyId("active-key");
        properties.getJwt().setRevokedKeyIds("revoked-key");
        JwtKeyService keys = new JwtKeyService(
                (RSAPublicKey) pair.getPublic(),
                (RSAPrivateKey) pair.getPrivate(),
                properties,
                new DefaultResourceLoader());
        var validator = new JwtConfig.KeyRevocationValidator(keys);

        assertTrue(validator.validate(jwt(Map.of("alg", "RS256"))).hasErrors());
        assertTrue(validator.validate(jwt(Map.of("kid", "unknown-key"))).hasErrors());
        assertTrue(validator.validate(jwt(Map.of("kid", "revoked-key"))).hasErrors());
        assertTrue(!validator.validate(jwt(Map.of("kid", "active-key"))).hasErrors());
    }

    private Jwt jwt(Map<String, Object> headers) {
        Instant now = Instant.now();
        return new Jwt("token", now, now.plusSeconds(60), headers, Map.of("sub", "subject"));
    }
}
