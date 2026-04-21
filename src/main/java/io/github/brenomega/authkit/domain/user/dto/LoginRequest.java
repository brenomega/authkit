package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * DTO defining the explicit whitelist of parameters allowed during login.
 *
 * <p> Only fields defined here accept incoming JSON data.</p>
 */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password
) {
}
