package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO for secure authenticated password change (RF 2.1.7).
 * 
 * <p>Requires both current and new password to prevent unauthorized hijacking
 * of active sessions.</p>
 */
public record PasswordChangeRequest(
    @NotBlank
    @Size(max = 128)
    String currentPassword,

    @NotBlank
    @Size(min = 12, max = 128)
    String newPassword
) {
}
