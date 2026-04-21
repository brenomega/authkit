package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO defining the explicit whitelist of parameters allowed during registration.
 *
 * <p><strong>Minimal Registration (RF 2.1.1):</strong> Only email and password are mandatory.
 * Other fields are optional.</p>
 *
 * <p><strong>Mass Assignment Protection:</strong> Only fields defined here
 * accept incoming JSON data. Any extra fields (e.g., trying to inject "role")
 * will be ignored or cause a 400 Bad Request due to strict duplicate
 * and unknown properties detection built into Jackson (DT 3.1.30).</p>
 */
public record RegisterRequest(
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        @AssertTrue(message = "Terms of Use must be accepted") boolean termsAccepted,
        @AssertTrue(message = "Privacy Policy must be accepted") boolean privacyPolicyAccepted
) {
}
