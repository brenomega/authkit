package io.github.brenomega.authkit.domain.user.util;

import java.security.SecureRandom;
import java.util.Base64;

/** Generates cryptographically random, unpadded URL-safe bearer-token material. */
public final class SecureTokenGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureTokenGenerator() {
    }

    /** Returns a token containing the requested number of random bytes before Base64 encoding. */
    public static String randomUrlSafeToken(int bytes) {
        byte[] token = new byte[bytes];
        SECURE_RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
