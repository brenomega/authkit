package io.github.brenomega.authkit.domain.mfa.util;

import java.util.Optional;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;

/**
 * Opaque MFA challenge token containing only lookup handles and random entropy.
 */
public final class MfaChallengeCodec {

    private static final String VERSION = "v1";
    private static final String PREFIX = "mfa";
    private static final int SECRET_BYTES = 32;
    private static final int MIN_SECRET_LENGTH = 32;

    private MfaChallengeCodec() {
    }

    public static IssuedMfaChallenge issue(String userId) {
        String jti = UUID.randomUUID().toString();
        String raw = PREFIX + "." + VERSION + "." + userId + "." + jti + "."
                + SecureTokenGenerator.randomUrlSafeToken(SECRET_BYTES);
        return new IssuedMfaChallenge(userId, jti, raw);
    }

    public static Optional<IssuedMfaChallenge> parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }

        String[] parts = rawToken.split("\\.", -1);
        if (parts.length != 5 || !PREFIX.equals(parts[0]) || !VERSION.equals(parts[1])
                || parts[4].length() < MIN_SECRET_LENGTH) {
            return Optional.empty();
        }

        try {
            UUID.fromString(parts[2]);
            UUID.fromString(parts[3]);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }

        return Optional.of(new IssuedMfaChallenge(parts[2], parts[3], rawToken));
    }

    public record IssuedMfaChallenge(String userId, String jti, String rawToken) {
    }
}
