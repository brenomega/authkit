package io.github.brenomega.authkit.service.spi;

import java.util.List;

/**
 * Carries one non-snapshot page of active refresh-session identifiers.
 *
 * @param items active session JTIs visible when the page was read
 * @param nextCursor opaque single-use continuation cursor, or {@code null} when
 *                   no continuation was observed
 */
public record SessionPage(List<String> items, String nextCursor) {
}
