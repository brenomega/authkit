package io.github.brenomega.authkit.domain.passkey.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record PasskeyAssertionOptionsRequest(
        @Email @Size(max = 255) String email
) {
}
