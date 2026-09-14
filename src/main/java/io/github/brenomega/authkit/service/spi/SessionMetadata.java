package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;

/**
 * Describes a revocable first-party session without exposing its refresh secret.
 *
 * <p>{@code publicSessionId} is safe to expose to the owning user and is distinct
 * from the internal JWT {@code jti}. IP values are already masked, and
 * {@code initialAmr} records the methods completed when the session was created;
 * callers must not treat later MFA configuration changes as rewriting it.</p>
 */
public record SessionMetadata(
        String publicSessionId,
        String jti,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        long securityVersion,
        List<String> initialAmr,
        String userAgentSummary,
        String deviceLabel,
        String creationIpMasked,
        String lastIpMasked) {

    public SessionMetadata {
        if (securityVersion < 0) {
            throw new IllegalArgumentException("securityVersion must not be negative");
        }
        initialAmr = initialAmr == null ? List.of() : List.copyOf(initialAmr);
    }
}
