package io.github.brenomega.authkit.domain.mfa.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Carries proof of the pending TOTP enrollment together with password step-up. */
public record MfaTotpConfirmRequest(
        @NotNull
        UUID credentialId,

        @NotBlank
        @Size(max = 128)
        String currentPassword,

        @NotBlank
        @Size(min = 6, max = 8)
        String code
) {
}
