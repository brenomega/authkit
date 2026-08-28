package io.github.brenomega.authkit.domain.user.dto;

/** Combines tenant-scoped account details with credential-secret-free authenticator status. */
public record AdminUserDetailResponse(AdminUserResponse user, AdminAuthenticatorStatus authenticators) {}
