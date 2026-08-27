package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

public record EmailChangeStatusResponse(
        String status,
        String pendingEmail,
        Instant requestedAt,
        Instant expiresAt) {
}
