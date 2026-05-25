package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/**
 * Current MFA posture for the authenticated user.
 */
public record MfaStatusResponse(
        boolean totpEnabled,
        int backupCodesRemaining,
        Instant enrolledAt
) {
}
