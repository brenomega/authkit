package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.List;

import io.github.brenomega.authkit.service.spi.SessionMetadata;

public record SessionResponse(
        String sessionId,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        boolean current,
        List<String> initialAmr,
        String userAgentSummary,
        String deviceLabel,
        String creationIpMasked,
        String lastIpMasked
) {
    public static SessionResponse from(SessionMetadata metadata, String currentJti) {
        return new SessionResponse(
                metadata.publicSessionId(), metadata.createdAt(), metadata.lastSeenAt(), metadata.expiresAt(),
                metadata.jti().equals(currentJti), metadata.initialAmr(), metadata.userAgentSummary(),
                metadata.deviceLabel(), metadata.creationIpMasked(), metadata.lastIpMasked());
    }
}
