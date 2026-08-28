package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

/** Carries fresh password and optional MFA evidence for a sensitive authenticated operation. */
public record StepUpRequest(
        @Size(max = 128)
        String currentPassword,

        @Size(min = 6, max = 32)
        String mfaCode
) {
    public StepUpRequest(String currentPassword) {
        this(currentPassword, null);
    }
}
