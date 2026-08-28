package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

/** Carries privacy-reduced audit evidence and a query-bound continuation cursor. */
public record AdminSecurityEventPageResponse(List<AdminSecurityEventResponse> items, String nextCursor) {}
