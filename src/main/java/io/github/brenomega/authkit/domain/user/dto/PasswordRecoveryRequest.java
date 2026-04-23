package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for requesting a password recovery link (RF 2.1.3).
 *
 * <p>Used as the payload for the recovery initiation endpoint.</p>
 *
 * @param email the user's registered email address
 */
public record PasswordRecoveryRequest(
        @NotBlank @Email String email
) {
}
