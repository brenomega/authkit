package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.List;

public record FirstPartyIntrospectionResponse(
        boolean active,
        String subject,
        String tenantId,
        Instant expiresAt,
        String tokenUse,
        List<String> amr) {

    public static FirstPartyIntrospectionResponse inactive() {
        return new FirstPartyIntrospectionResponse(false, null, null, null, null, null);
    }
}
