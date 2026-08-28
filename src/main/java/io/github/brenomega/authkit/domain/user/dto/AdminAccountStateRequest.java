package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries a state transition reason and fresh administrative step-up evidence. */
public record AdminAccountStateRequest(
        @NotBlank @Size(max = 500) String reason,
        @Size(max = 128) String currentPassword,
        @Size(max = 32) String mfaCode
) {
}
