package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Secret bootstrap document read only from stdin or a mounted file. */
public record BootstrapAdminRequest(
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        @Size(max = 100) String name,
        @AssertTrue(message = "Terms of Use must be accepted") boolean termsAccepted,
        @AssertTrue(message = "Privacy Policy must be accepted") boolean privacyPolicyAccepted
) {
}
