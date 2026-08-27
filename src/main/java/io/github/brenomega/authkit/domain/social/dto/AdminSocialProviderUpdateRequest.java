package io.github.brenomega.authkit.domain.social.dto;

import java.util.Set;
import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record AdminSocialProviderUpdateRequest(
        @NotBlank @Size(max = 120) String displayName,
        @NotBlank @Size(max = 255) String clientId,
        @Size(max = 2048) String clientSecret,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 80) String> scopes,
        OidcClientAuthMethod clientAuthMethod,
        @Size(max = 128) String currentPassword,
        @Size(max = 32) String mfaCode) {}
