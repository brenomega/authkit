package io.github.brenomega.authkit.domain.user.dto;

import io.github.brenomega.authkit.domain.user.enums.Role;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record AdminUpdateRoleRequest(
        @NotNull Role role,
        @Size(max = 128) String currentPassword,
        @Size(max = 32) String mfaCode
) {
    public AdminUpdateRoleRequest(Role role, String mfaCode) {
        this(role, null, mfaCode);
    }
}
