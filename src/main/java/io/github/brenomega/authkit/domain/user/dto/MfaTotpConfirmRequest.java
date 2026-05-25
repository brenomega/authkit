package io.github.brenomega.authkit.domain.user.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Confirms a pending TOTP credential and returns one-time backup codes.
 */
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
