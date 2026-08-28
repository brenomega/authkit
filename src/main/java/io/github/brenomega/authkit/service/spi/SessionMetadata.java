package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;

public record SessionMetadata(
        String publicSessionId,
        String jti,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        List<String> initialAmr,
        String userAgentSummary,
        String deviceLabel,
        String creationIpMasked,
        String lastIpMasked) {

    public SessionMetadata {
        initialAmr = initialAmr == null ? List.of() : List.copyOf(initialAmr);
    }
}
