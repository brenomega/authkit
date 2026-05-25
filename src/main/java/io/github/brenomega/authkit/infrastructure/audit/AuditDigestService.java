package io.github.brenomega.authkit.infrastructure.audit;

import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

@Service
public class AuditDigestService {

    private static final String HMAC_SHA_256 = "HmacSHA256";

    private final AuthProperties authProperties;

    public AuditDigestService(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    public String hashNullable(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return hmacHex(value);
    }

    public String hmacHex(String value) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            SecretKeySpec key = new SecretKeySpec(
                    authProperties.getAudit().getHashPepper().getBytes(StandardCharsets.UTF_8),
                    HMAC_SHA_256);
            mac.init(key);
            return toHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", ex);
        }
    }

    private String toHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            hex[i * 2] = alphabet[value >>> 4];
            hex[i * 2 + 1] = alphabet[value & 0x0F];
        }
        return new String(hex);
    }
}
