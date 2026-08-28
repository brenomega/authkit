package io.github.brenomega.authkit.domain.user.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates high-entropy URL-safe secrets from the process {@link SecureRandom}.
 */
public final class SecureTokenGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureTokenGenerator() {
    }

    /**
     * Returns an unpadded Base64URL token backed by the requested random-byte count.
     *
     * @param bytes entropy source length in bytes, not output characters
     */
    public static String randomUrlSafeToken(int bytes) {
        byte[] token = new byte[bytes];
        SECURE_RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
