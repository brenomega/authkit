package io.github.brenomega.authkit.service.spi;

import java.util.List;

/**
 * Carries one non-snapshot page of active refresh-session metadata.
 *
 * @param items active sessions visible when the page was read
 * @param nextCursor opaque single-use continuation cursor, or {@code null} when
 *                   no continuation was observed
 */
public record SessionPage(List<SessionMetadata> items, String nextCursor) {
}
