package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/** Describes pending email-change state without exposing the confirmation secret. */
public record EmailChangeStatusResponse(
        String status,
        String pendingEmail,
        Instant requestedAt,
        Instant expiresAt) {
}
