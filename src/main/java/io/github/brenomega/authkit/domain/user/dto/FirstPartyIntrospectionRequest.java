package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries a first-party bearer token across the trusted worker boundary. */
public record FirstPartyIntrospectionRequest(
        @NotBlank @Size(max = 8192) String token) {
}
