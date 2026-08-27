package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

public record AdminUserPageResponse(List<AdminUserResponse> items, String nextCursor) {}
