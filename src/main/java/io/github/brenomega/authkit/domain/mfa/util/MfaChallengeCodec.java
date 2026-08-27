package io.github.brenomega.authkit.domain.mfa.util;

import java.util.Optional;
import java.util.UUID;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;

/**
 * Opaque MFA challenge token containing only lookup handles and random entropy.
 */
public final class MfaChallengeCodec {

    private static final String VERSION = "v1";
    private static final String VERSION_WITH_AMR = "v2";
    private static final String PREFIX = "mfa";
    private static final int SECRET_BYTES = 32;
    private static final int MIN_SECRET_LENGTH = 32;

    private MfaChallengeCodec() {
    }

    public static IssuedMfaChallenge issue(String userId) {
        return issue(userId, List.of("pwd"));
    }

    public static IssuedMfaChallenge issue(String userId, List<String> initialAmr) {
        String jti = UUID.randomUUID().toString();
        String encodedAmr = Base64.getUrlEncoder().withoutPadding().encodeToString(
                String.join(",", initialAmr).getBytes(StandardCharsets.UTF_8));
        String raw = PREFIX + "." + VERSION_WITH_AMR + "." + userId + "." + jti + "." + encodedAmr + "."
                + SecureTokenGenerator.randomUrlSafeToken(SECRET_BYTES);
        return new IssuedMfaChallenge(userId, jti, raw, List.copyOf(initialAmr));
    }

    public static Optional<IssuedMfaChallenge> parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }

        String[] parts = rawToken.split("\\.", -1);
        boolean legacy = parts.length == 5 && PREFIX.equals(parts[0]) && VERSION.equals(parts[1]);
        boolean versionedAmr = parts.length == 6 && PREFIX.equals(parts[0]) && VERSION_WITH_AMR.equals(parts[1]);
        if ((!legacy && !versionedAmr) || parts[parts.length - 1].length() < MIN_SECRET_LENGTH) {
            return Optional.empty();
        }

        try {
            UUID.fromString(parts[2]);
            UUID.fromString(parts[3]);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }

        List<String> initialAmr = List.of("pwd");
        if (versionedAmr) {
            try {
                String decoded = new String(Base64.getUrlDecoder().decode(parts[4]), StandardCharsets.UTF_8);
                initialAmr = java.util.Arrays.stream(decoded.split(","))
                        .filter(value -> value.matches("[a-z0-9:_-]{1,80}"))
                        .distinct()
                        .toList();
            } catch (IllegalArgumentException ex) {
                return Optional.empty();
            }
            if (initialAmr.isEmpty()) return Optional.empty();
        }
        return Optional.of(new IssuedMfaChallenge(parts[2], parts[3], rawToken, initialAmr));
    }

    public record IssuedMfaChallenge(String userId, String jti, String rawToken, List<String> initialAmr) {
    }
}
