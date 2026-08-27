package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

/**
 * DTO dictating the properties available for patch/update during a profile edit.
 * 
 * <p>Includes optional properties (RF 2.1.6) editable via the profile update flow (RF 2.1.7).</p>
 */
public record ProfileUpdateRequest(
        @Size(max = 100) String name
) {
}
