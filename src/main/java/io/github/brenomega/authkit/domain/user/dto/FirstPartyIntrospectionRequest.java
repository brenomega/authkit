package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record FirstPartyIntrospectionRequest(
        @NotBlank @Size(max = 8192) String token) {
}
