package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.UUID;

/** Carries one-time TOTP enrollment material that must not be retained by clients. */
public record MfaTotpEnrollmentResponse(
        UUID credentialId,
        String secret,
        String otpauthUri
) {
}
