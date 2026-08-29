package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Owns active JWT signing material and the public key-rotation view.
 *
 * <p>The active private RSA key is used only for signing. JWKS publication includes
 * the active public key and configured retiring public keys, excluding every
 * revoked key ID. Retiring entries are verification-only and do not change the
 * key ID used for newly issued tokens.</p>
 */
@Service
public class JwtKeyService {

    private final RSAPublicKey activePublicKey;
    private final RSAPrivateKey activePrivateKey;
    private final AuthProperties authProperties;
    private final ResourceLoader resourceLoader;
    private final JWKSet publishedPublicKeys;

    public JwtKeyService(@Value("${jwt.public.key}") RSAPublicKey activePublicKey,
                         @Value("${jwt.private.key}") RSAPrivateKey activePrivateKey,
                         AuthProperties authProperties,
                         ResourceLoader resourceLoader) {
        this.activePublicKey = activePublicKey;
        this.activePrivateKey = activePrivateKey;
        this.authProperties = authProperties;
        this.resourceLoader = resourceLoader;
        validateConfiguration();
        this.publishedPublicKeys = buildPublishedPublicJwkSet();
    }

    public RSAPublicKey activePublicKey() {
        return activePublicKey;
    }

    public RSAKey activePrivateJwk() {
        return new RSAKey.Builder(activePublicKey)
                .keyID(authProperties.getJwt().getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .privateKey(activePrivateKey)
                .build();
    }

    /** Returns the active and retiring verification keys after revoked IDs are removed. */
    public JWKSet publishedPublicJwkSet() {
        return publishedPublicKeys;
    }

    private JWKSet buildPublishedPublicJwkSet() {
        Set<RSAKey> keys = new LinkedHashSet<>();
        RSAKey active = publicJwk(authProperties.getJwt().getKeyId(), activePublicKey);
        if (!isRevokedKid(active.getKeyID())) {
            keys.add(active);
        }
        parseRetiringPublicKeys().forEach(key -> {
            if (!isRevokedKid(key.getKeyID())) {
                keys.add(key);
            }
        });
        return new JWKSet(keys.stream().map(key -> (JWK) key).toList());
    }

    public boolean isRevokedKid(String kid) {
        return revokedKeyIds().contains(kid);
    }

    /** Returns whether a non-revoked key ID is present in the current JWKS view. */
    public boolean isPublishedKid(String kid) {
        return kid != null && publishedPublicKeys.getKeys().stream()
                .anyMatch(key -> kid.equals(key.getKeyID()));
    }

    public Set<String> revokedKeyIds() {
        return Optional.ofNullable(authProperties.getJwt().getRevokedKeyIds())
                .filter(value -> !value.isBlank())
                .map(value -> Arrays.stream(value.split("[,;]"))
                        .map(String::trim)
                        .filter(item -> !item.isBlank())
                        .collect(Collectors.toUnmodifiableSet()))
                .orElseGet(Set::of);
    }

    private Set<RSAKey> parseRetiringPublicKeys() {
        return Optional.ofNullable(authProperties.getJwt().getRetiringPublicKeys())
                .filter(value -> !value.isBlank())
                .map(value -> {
                    Set<RSAKey> keys = Arrays.stream(value.split(";"))
                            .map(String::trim)
                            .filter(entry -> !entry.isBlank())
                            .map(this::parseRetiringPublicKey)
                            .collect(Collectors.toCollection(LinkedHashSet::new));
                    return keys;
                })
                .orElseGet(Set::of);
    }

    private void validateConfiguration() {
        String activeKeyId = authProperties.getJwt().getKeyId();
        if (activeKeyId == null || !activeKeyId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalStateException("JWT active key ID is invalid.");
        }
        List<String> revokedEntries = Optional.ofNullable(authProperties.getJwt().getRevokedKeyIds())
                .filter(value -> !value.isBlank())
                .map(value -> Arrays.stream(value.split("[,;]"))
                        .map(String::trim)
                        .filter(item -> !item.isBlank())
                        .toList())
                .orElseGet(List::of);
        if (new LinkedHashSet<>(revokedEntries).size() != revokedEntries.size()) {
            throw new IllegalStateException("JWT revoked key IDs contain duplicates.");
        }
        if (revokedEntries.contains(activeKeyId)) {
            throw new IllegalStateException("JWT active key ID cannot be revoked.");
        }

        Set<String> publishedIds = new LinkedHashSet<>();
        publishedIds.add(activeKeyId);
        for (RSAKey retiringKey : parseRetiringPublicKeys()) {
            String retiringId = retiringKey.getKeyID();
            if (retiringId == null || !retiringId.matches("[A-Za-z0-9._-]{1,64}")) {
                throw new IllegalStateException("JWT retiring key ID is invalid.");
            }
            if (!publishedIds.add(retiringId)) {
                throw new IllegalStateException("JWT published key IDs contain duplicates.");
            }
        }
    }

    private RSAKey parseRetiringPublicKey(String entry) {
        int separator = entry.indexOf('=');
        if (separator <= 0 || separator == entry.length() - 1) {
            throw new IllegalStateException("JWT retiring public keys must use keyId=PEM_OR_RESOURCE entries.");
        }
        String keyId = entry.substring(0, separator).trim();
        String keyMaterial = entry.substring(separator + 1).trim();
        return publicJwk(keyId, parsePublicKey(keyMaterial));
    }

    private RSAPublicKey parsePublicKey(String keyMaterial) {
        try {
            String pem = loadKeyMaterial(keyMaterial);
            String normalized = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(normalized);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to parse JWT retiring public key", ex);
        }
    }

    private String loadKeyMaterial(String keyMaterial) throws IOException {
        if (keyMaterial.startsWith("classpath:") || keyMaterial.startsWith("file:")) {
            Resource resource = resourceLoader.getResource(keyMaterial);
            return StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        }
        return keyMaterial;
    }

    private RSAKey publicJwk(String keyId, RSAPublicKey publicKey) {
        return new RSAKey.Builder(publicKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }
}
