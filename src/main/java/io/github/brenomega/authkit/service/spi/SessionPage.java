package io.github.brenomega.authkit.service.spi;

import java.util.List;

public record SessionPage(List<SessionMetadata> items, String nextCursor) {
}
