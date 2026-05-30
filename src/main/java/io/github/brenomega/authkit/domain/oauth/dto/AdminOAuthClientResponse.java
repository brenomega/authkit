package io.github.brenomega.authkit.domain.oauth.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record AdminOAuthClientResponse(
        UUID id,
        UUID tenantId,
        String clientId,
        String clientSecret,
        boolean publicClient,
        String displayName,
        Set<String> redirectUris,
        Set<String> scopes,
        boolean requirePkce,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt,
        Instant disabledAt
) {
}
