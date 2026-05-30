package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.UUID;

/**
 * One-time TOTP enrollment material. The secret is returned only during setup.
 */
public record MfaTotpEnrollmentResponse(
        UUID credentialId,
        String secret,
        String otpauthUri
) {
}
