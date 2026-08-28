package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

/** Carries an administrative account page and its caller-bound continuation cursor. */
public record AdminUserPageResponse(List<AdminUserResponse> items, String nextCursor) {}
