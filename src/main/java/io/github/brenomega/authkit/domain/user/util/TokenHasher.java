package io.github.brenomega.authkit.domain.user.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes deterministic SHA-256 token digests for exact server-side lookup.
 *
 * <p>Callers remain responsible for constant-time digest comparison. This helper
 * is not a password encoder and provides no work factor.</p>
 */
public final class TokenHasher {

    private TokenHasher() {
    }

    /** Returns the lowercase hexadecimal SHA-256 digest of the exact UTF-8 token. */
    public static String sha256Hex(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return bytesToHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Required cryptographic algorithm not found", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
