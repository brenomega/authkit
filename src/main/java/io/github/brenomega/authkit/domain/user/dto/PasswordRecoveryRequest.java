package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** Carries an email into an enumeration-resistant recovery request. */
public record PasswordRecoveryRequest(
        @NotBlank @Email String email
) {
}
