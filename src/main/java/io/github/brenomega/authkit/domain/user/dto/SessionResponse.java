package io.github.brenomega.authkit.domain.user.dto;

/**
 * DTO representing an active authentication session (RF 2.1.8).
 * 
 * <p>Exposes the session identifier (JTI) used for individual revocation (DT 3.1.18).</p>
 */
public record SessionResponse(
    String jti
) {
}
