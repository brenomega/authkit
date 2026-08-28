package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.List;

public record MfaBackupCodesResponse(
        List<String> backupCodes
) {
}
