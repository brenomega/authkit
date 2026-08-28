package io.github.brenomega.authkit.domain.user.dto;

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
