package io.github.brenomega.authkit.service.spi;

import java.util.List;

public record SessionPage(List<String> items, String nextCursor) {
}
