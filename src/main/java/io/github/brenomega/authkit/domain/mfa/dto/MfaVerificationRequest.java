package io.github.brenomega.authkit.domain.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries password and MFA evidence for an authenticator-policy change. */
public record MfaVerificationRequest(
        @Size(max = 128)
        String currentPassword,

        @NotBlank
        @Size(min = 6, max = 32)
        String code
) {
}
