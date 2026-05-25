package io.github.brenomega.authkit.domain.user.dto;

/**
 * DTO returned after a successful user login.
 *
 * <p>Exposes the JWT access token and its expiration time.</p>
 */
public record LoginResponse(
        String accessToken,
        long expiresIn,
        boolean mfaRequired,
        String mfaToken
) {
    public LoginResponse(String accessToken, long expiresIn) {
        this(accessToken, expiresIn, false, null);
    }

    public static LoginResponse mfaRequired(String mfaToken) {
        return new LoginResponse(null, 0, true, mfaToken);
    }
}
