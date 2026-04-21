package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

/**
 * DTO dictating the properties available for patch/update during a profile edit.
 */
public record ProfileUpdateRequest(
        @Size(max = 100) String name,
        @Size(max = 20) String phone
) {
}
