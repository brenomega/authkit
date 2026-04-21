package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO defining the explicit whitelist of parameters allowed during registration.
 *
 * <p><strong>Mass Assignment Protection:</strong> Only fields defined here
 * accept incoming JSON data. Any extra fields (e.g., trying to inject "role")
 * will either be ignored or cause a 400 Bad Request due to strict duplicate
 * and unknown properties detection built into Jackson.</p>
 */
public record RegisterRequest(
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        @Size(max = 100) String name,
        @Size(max = 20) String phone,
        @AssertTrue(message = "Terms of Use must be accepted") boolean termsAccepted,
        @AssertTrue(message = "Privacy Policy must be accepted") boolean privacyPolicyAccepted
) {
}
