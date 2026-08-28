package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

/** Carries a page of active sessions and an opaque single-use continuation cursor. */
public record SessionPageResponse(List<SessionResponse> items, String nextCursor) {
}
