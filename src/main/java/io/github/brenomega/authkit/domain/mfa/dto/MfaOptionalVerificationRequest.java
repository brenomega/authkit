package io.github.brenomega.authkit.domain.mfa.dto;

import jakarta.validation.constraints.Size;

/**
 * Optional MFA proof used by operations that require it only when MFA is enabled.
 */
public record MfaOptionalVerificationRequest(
        @Size(max = 128)
        String currentPassword,

        @Size(min = 6, max = 32)
        String code
) {
    public MfaOptionalVerificationRequest(String code) {
        this(null, code);
    }
}
