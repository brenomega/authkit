package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

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

@Service
public class JwtKeyService {

    private final RSAPublicKey activePublicKey;
    private final RSAPrivateKey activePrivateKey;
    private final AuthProperties authProperties;
    private final ResourceLoader resourceLoader;

    public JwtKeyService(@Value("${jwt.public.key}") RSAPublicKey activePublicKey,
                         @Value("${jwt.private.key}") RSAPrivateKey activePrivateKey,
                         AuthProperties authProperties,
                         ResourceLoader resourceLoader) {
        this.activePublicKey = activePublicKey;
        this.activePrivateKey = activePrivateKey;
        this.authProperties = authProperties;
        this.resourceLoader = resourceLoader;
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

    public JWKSet publishedPublicJwkSet() {
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

    public Set<String> revokedKeyIds() {
        String value = authProperties.getJwt().getRevokedKeyIds();
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split("[,;]"))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }

    private Set<RSAKey> parseRetiringPublicKeys() {
        String value = authProperties.getJwt().getRetiringPublicKeys();
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(";"))
                .map(String::trim)
                .filter(entry -> !entry.isBlank())
                .map(this::parseRetiringPublicKey)
                .collect(Collectors.toCollection(LinkedHashSet::new));
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
            byte[] der = java.util.Base64.getDecoder().decode(normalized);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to parse JWT retiring public key", ex);
        }
    }

    private String loadKeyMaterial(String keyMaterial) throws IOException {
        if (keyMaterial.startsWith("classpath:") || keyMaterial.startsWith("file:")) {
            Resource resource = resourceLoader.getResource(keyMaterial);
            final Charset utf_82 = StandardCharsets.UTF_8;
            if (utf_82 != null) {
                return StreamUtils.copyToString(resource.getInputStream(), utf_82);
            } else {
                // TODO handle null value
                return null;
            }
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
