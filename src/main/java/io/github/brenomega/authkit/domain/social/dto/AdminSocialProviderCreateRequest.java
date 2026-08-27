package io.github.brenomega.authkit.domain.social.dto;

import java.util.Set;
import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import io.github.brenomega.authkit.domain.social.entity.SocialProviderType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record AdminSocialProviderCreateRequest(
        @NotBlank @Pattern(regexp = "[a-z0-9][a-z0-9_-]{1,63}") String providerKey,
        @NotBlank @Size(max = 120) String displayName,
        SocialProviderType providerType,
        @NotBlank @Size(max = 512) String issuer,
        @NotBlank @Size(max = 255) String clientId,
        @NotBlank @Size(max = 2048) String clientSecret,
        @NotEmpty @Size(max = 20) Set<@NotBlank @Size(max = 80) String> scopes,
        OidcClientAuthMethod clientAuthMethod,
        @Size(max = 128) String currentPassword,
        @Size(max = 32) String mfaCode) {}
