package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

public record SessionPageResponse(List<SessionResponse> items, String nextCursor) {
}
