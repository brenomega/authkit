package io.github.brenomega.authkit.domain.oauth.dto;

import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record AdminOAuthClientCreateRequest(
        @NotBlank @Size(max = 120) String displayName,
        boolean publicClient,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 512) String> redirectUris,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 80) String> scopes,
        boolean requirePkce,
        @Size(max = 128) String currentPassword,
        @Size(max = 32) String mfaCode
) {
    public AdminOAuthClientCreateRequest(String displayName,
                                         boolean publicClient,
                                         Set<String> redirectUris,
                                         Set<String> scopes,
                                         boolean requirePkce,
                                         String mfaCode) {
        this(displayName, publicClient, redirectUris, scopes, requirePkce, null, mfaCode);
    }
}
