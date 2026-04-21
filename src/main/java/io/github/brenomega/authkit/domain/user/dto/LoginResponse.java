package io.github.brenomega.authkit.domain.user.dto;

/**
 * DTO returned after a successful user login.
 *
 * <p>Exposes the JWT access token and its expiration time.</p>
 */
public record LoginResponse(
        String accessToken,
        long expiresIn
) {
}
