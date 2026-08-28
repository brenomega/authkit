package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.UUID;

public record MfaTotpEnrollmentResponse(
        UUID credentialId,
        String secret,
        String otpauthUri
) {
}
