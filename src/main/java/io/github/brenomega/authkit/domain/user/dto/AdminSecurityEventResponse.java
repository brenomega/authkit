package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.UUID;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;

public record AdminSecurityEventResponse(
        UUID id, Instant occurredAt, SecurityEventType type, SecurityEventOutcome outcome,
        SecurityEventSeverity severity, UUID actorUserId, UUID targetUserId,
        String emailMasked, String clientIpMasked, String reason, String metadataJson
) {}
