package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

/**
 * Optional MFA proof used by operations that require it only when MFA is enabled.
 */
public record MfaOptionalVerificationRequest(
        @Size(min = 6, max = 32)
        String code
) {
}
