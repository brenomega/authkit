package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO defining the explicit whitelist of parameters allowed during login.
 *
 * <p> Only fields defined here accept incoming JSON data.</p>
 */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(max = 128) String password
) {
}
