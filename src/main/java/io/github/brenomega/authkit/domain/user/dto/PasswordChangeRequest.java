package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
    @Size(max = 128)
    String currentPassword,

    @NotBlank
    @Size(min = 12, max = 128)
    String newPassword,

    @Size(min = 6, max = 32)
    String mfaCode
) {
    public PasswordChangeRequest(String currentPassword, String newPassword) {
        this(currentPassword, newPassword, null);
    }
}
