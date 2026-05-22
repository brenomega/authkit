package io.github.brenomega.authkit.domain.user.util;

import java.util.Optional;
import java.util.UUID;

/**
 * Encodes opaque refresh tokens with enough public handle data to locate the
 * server-side hashed token record.
 */
public final class RefreshTokenCodec {

    private static final String VERSION = "v1";
    private static final int SECRET_BYTES = 32;
    private static final int MIN_SECRET_LENGTH = 32;

    private RefreshTokenCodec() {
    }

    public static IssuedRefreshToken issue(String userId, String jti) {
        String token = VERSION + "." + userId + "." + jti + "."
                + SecureTokenGenerator.randomUrlSafeToken(SECRET_BYTES);
        return new IssuedRefreshToken(userId, jti, token);
    }

    public static Optional<IssuedRefreshToken> parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }

        String[] parts = rawToken.split("\\.", -1);
        if (parts.length != 4 || !VERSION.equals(parts[0]) || parts[3].length() < MIN_SECRET_LENGTH) {
            return Optional.empty();
        }

        try {
            UUID.fromString(parts[1]);
            UUID.fromString(parts[2]);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }

        return Optional.of(new IssuedRefreshToken(parts[1], parts[2], rawToken));
    }

    public record IssuedRefreshToken(String userId, String jti, String rawToken) {
    }
}
