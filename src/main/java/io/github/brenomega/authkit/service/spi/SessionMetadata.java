package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;

/**
 * Privacy-preserving metadata exposed for a first-party login session.
 *
 * <p>The internal JWT identifier is deliberately kept inside the SPI and must
 * never be serialized by public controllers. Callers revoke sessions through
 * {@link #publicSessionId()}.</p>
 */
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
