package io.github.brenomega.authkit.domain.mfa.dto;

import jakarta.validation.constraints.Size;

/** Carries an MFA factor when the target account's current policy requires one. */
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
