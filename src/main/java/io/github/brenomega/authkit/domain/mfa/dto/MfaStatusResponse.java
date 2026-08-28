package io.github.brenomega.authkit.domain.mfa.dto;

import java.time.Instant;

public record MfaStatusResponse(
        boolean totpEnabled,
        int backupCodesRemaining,
        Instant enrolledAt
) {
}
