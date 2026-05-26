package io.github.brenomega.authkit.domain.user.dto;

import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record AdminOAuthClientUpdateRequest(
        @NotBlank @Size(max = 120) String displayName,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 512) String> redirectUris,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 80) String> scopes,
        boolean requirePkce,
        @Size(max = 32) String mfaCode
) {
}
