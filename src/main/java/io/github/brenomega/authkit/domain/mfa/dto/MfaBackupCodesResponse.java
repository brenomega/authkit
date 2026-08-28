package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.List;

/** Carries the only plaintext copy of newly generated single-use backup codes. */
public record MfaBackupCodesResponse(
        List<String> backupCodes
) {
}
