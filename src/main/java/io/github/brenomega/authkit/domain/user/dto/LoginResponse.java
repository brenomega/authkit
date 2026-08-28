package io.github.brenomega.authkit.domain.user.dto;

/** Carries public authentication state; refresh secrets remain in the controller cookie boundary. */
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
