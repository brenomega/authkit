package io.github.brenomega.authkit.domain.user.dto;

public record AdminUserDetailResponse(AdminUserResponse user, AdminAuthenticatorStatus authenticators) {}
