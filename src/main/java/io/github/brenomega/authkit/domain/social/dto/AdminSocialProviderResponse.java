package io.github.brenomega.authkit.domain.social.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import io.github.brenomega.authkit.domain.social.entity.SocialProviderType;

public record AdminSocialProviderResponse(UUID id, String providerKey, String displayName,
        SocialProviderType providerType, String issuer, String clientId, Set<String> scopes,
        OidcClientAuthMethod clientAuthMethod, boolean enabled, Instant createdAt,
        Instant updatedAt, Instant disabledAt) {}
