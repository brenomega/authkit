package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import io.github.brenomega.authkit.util.RsaKeyGenerator;

class JwtKeyServiceTest {

    @Test
    @DisplayName("Publishes active and retiring JWT keys while hiding revoked key IDs")
    void publishedPublicJwkSet_supportsRotationAndRevocation() {
        var active = RsaKeyGenerator.generateKeyPair();
        var retiring = RsaKeyGenerator.generateKeyPair();
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setKeyId("active-key");
        properties.getJwt().setRetiringPublicKeys("old-key=" + RsaKeyGenerator.toPublicPem(retiring.getPublic()));
        properties.getJwt().setRevokedKeyIds("revoked-key");

        JwtKeyService keyService = new JwtKeyService(
                (RSAPublicKey) active.getPublic(),
                (RSAPrivateKey) active.getPrivate(),
                properties,
                new DefaultResourceLoader());

        Set<String> keyIds = keyService.publishedPublicJwkSet().getKeys().stream()
                .map(key -> key.getKeyID())
                .collect(Collectors.toSet());

        assertEquals(Set.of("active-key", "old-key"), keyIds);
        assertTrue(keyService.isRevokedKid("revoked-key"));
        assertFalse(keyService.isRevokedKid("active-key"));
    }
}
