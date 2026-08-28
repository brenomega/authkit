package io.github.brenomega.authkit.domain.user.util;

import java.util.Optional;
import java.util.UUID;

/**
 * Encodes refresh secrets with public handles for server-side session lookup.
 *
 * <p>The user, session JTI, and family ID are routing metadata, not trusted
 * authentication claims. A token is authenticated only after its entire raw value
 * matches the server-side hash.</p>
 */
public final class RefreshTokenCodec {

    private static final String VERSION = "v1";
    private static final int SECRET_BYTES = 32;
    private static final int MIN_SECRET_LENGTH = 32;

    private RefreshTokenCodec() {
    }

    /**
     * Issues a fresh refresh token with a new token family identifier.
     */
    public static IssuedRefreshToken issue(String userId, String jti) {
        String familyId = UUID.randomUUID().toString();
        String token = VERSION + "." + userId + "." + jti + "." + familyId + "."
                + SecureTokenGenerator.randomUrlSafeToken(SECRET_BYTES);
        return new IssuedRefreshToken(userId, jti, familyId, token);
    }

    /**
     * Issues a rotated refresh token, preserving the existing token family identifier.
     */
    public static IssuedRefreshToken issueRotated(String userId, String jti, String familyId) {
        String token = VERSION + "." + userId + "." + jti + "." + familyId + "."
                + SecureTokenGenerator.randomUrlSafeToken(SECRET_BYTES);
        return new IssuedRefreshToken(userId, jti, familyId, token);
    }

    /**
     * Parses structural handles without authenticating the token secret.
     *
     * @return parsed metadata when version, UUIDs, and minimum secret length are valid
     */
    public static Optional<IssuedRefreshToken> parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }

        String[] parts = rawToken.split("\\.", -1);
        if (parts.length != 5 || !VERSION.equals(parts[0]) || parts[4].length() < MIN_SECRET_LENGTH) {
            return Optional.empty();
        }

        try {
            UUID.fromString(parts[1]);
            UUID.fromString(parts[2]);
            UUID.fromString(parts[3]);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }

        return Optional.of(new IssuedRefreshToken(parts[1], parts[2], parts[3], rawToken));
    }

    /**
     * Carries refresh-token routing metadata together with the raw secret-bearing value.
     */
    public record IssuedRefreshToken(String userId, String jti, String familyId, String rawToken) {
    }
}
