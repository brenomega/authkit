package io.github.brenomega.authkit.domain.mfa.dto;

import java.time.Instant;

/** Describes public TOTP enrollment state and remaining unused backup-code count. */
public record MfaStatusResponse(
        boolean totpEnabled,
        int backupCodesRemaining,
        Instant enrolledAt
) {
}
