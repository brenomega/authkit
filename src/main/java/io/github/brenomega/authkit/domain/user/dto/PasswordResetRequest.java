package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Data Transfer Object for resetting the password using a recovery token (RF 2.1.4).
 *
 * @param token       the high-entropy recovery token received via email
 * @param newPassword the new password to be set (Argon2id)
 */
public record PasswordResetRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 8) String newPassword
) {
}
