package io.github.brenomega.authkit.domain.user.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates high-entropy URL-safe tokens for authentication flows.
 */
public final class SecureTokenGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureTokenGenerator() {
    }

    public static String randomUrlSafeToken(int bytes) {
        byte[] token = new byte[bytes];
        SECURE_RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
