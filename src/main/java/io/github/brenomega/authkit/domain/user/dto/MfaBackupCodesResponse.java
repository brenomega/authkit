package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

/**
 * One-time backup codes. Raw codes are returned only immediately after creation.
 */
public record MfaBackupCodesResponse(
        List<String> backupCodes
) {
}
