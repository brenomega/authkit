package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import io.github.brenomega.authkit.util.RsaKeyGenerator;

class JwtKeyServiceTest {

    @TempDir
    Path temporaryDirectory;

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

    @Test
    @DisplayName("Loads a retiring public key from a configured file resource")
    void publishedPublicJwkSet_loadsRetiringKeyFromFileResource() throws Exception {
        var active = RsaKeyGenerator.generateKeyPair();
        var retiring = RsaKeyGenerator.generateKeyPair();
        Path retiringKey = temporaryDirectory.resolve("retiring-public-key.pem");
        Files.writeString(retiringKey, RsaKeyGenerator.toPublicPem(retiring.getPublic()));

        AuthProperties properties = new AuthProperties();
        properties.getJwt().setKeyId("active-key");
        properties.getJwt().setRetiringPublicKeys("old-key=" + retiringKey.toUri());

        JwtKeyService keyService = new JwtKeyService(
                (RSAPublicKey) active.getPublic(),
                (RSAPrivateKey) active.getPrivate(),
                properties,
                new DefaultResourceLoader());

        Set<String> keyIds = keyService.publishedPublicJwkSet().getKeys().stream()
                .map(key -> key.getKeyID())
                .collect(Collectors.toSet());

        assertEquals(Set.of("active-key", "old-key"), keyIds);
    }

    @Test
    void rejectsActiveRevokedAndDuplicateKeyIdentifiers() {
        var active = RsaKeyGenerator.generateKeyPair();
        var retiring = RsaKeyGenerator.generateKeyPair();

        AuthProperties activeRevoked = new AuthProperties();
        activeRevoked.getJwt().setKeyId("active-key");
        activeRevoked.getJwt().setRevokedKeyIds("active-key");
        assertThrows(IllegalStateException.class, () -> keyService(active, activeRevoked));

        AuthProperties duplicateRevoked = new AuthProperties();
        duplicateRevoked.getJwt().setKeyId("active-key");
        duplicateRevoked.getJwt().setRevokedKeyIds("old-key,old-key");
        assertThrows(IllegalStateException.class, () -> keyService(active, duplicateRevoked));

        AuthProperties duplicatePublished = new AuthProperties();
        duplicatePublished.getJwt().setKeyId("active-key");
        duplicatePublished.getJwt().setRetiringPublicKeys(
                "active-key=" + RsaKeyGenerator.toPublicPem(retiring.getPublic()));
        assertThrows(IllegalStateException.class, () -> keyService(active, duplicatePublished));
    }

    private JwtKeyService keyService(java.security.KeyPair active, AuthProperties properties) {
        return new JwtKeyService(
                (RSAPublicKey) active.getPublic(),
                (RSAPrivateKey) active.getPrivate(),
                properties,
                new DefaultResourceLoader());
    }
}
