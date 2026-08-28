package io.github.brenomega.authkit.domain.passkey.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

/** Selects a username-bound assertion when email is present, or a discoverable assertion otherwise. */
public record PasskeyAssertionOptionsRequest(
        @Email @Size(max = 255) String email
) {
}
