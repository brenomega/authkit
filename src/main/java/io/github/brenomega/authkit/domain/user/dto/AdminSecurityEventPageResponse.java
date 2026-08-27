package io.github.brenomega.authkit.domain.user.dto;

import java.util.List;

public record AdminSecurityEventPageResponse(List<AdminSecurityEventResponse> items, String nextCursor) {}
