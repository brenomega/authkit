package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;

/** Binds explicit acceptance to the exact policy versions presented to the user. */
public record ConsentAcceptanceRequest(
        @AssertTrue boolean termsAccepted,
        @AssertTrue boolean privacyPolicyAccepted,
        @NotBlank String termsVersion,
        @NotBlank String privacyPolicyVersion) {
}
