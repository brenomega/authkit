package io.github.brenomega.authkit.domain.user.util;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Centralizes extraction of the tenant identifier from JWT claims.
 *
 * <p>Performs a canonical lookup on the {@code tenant_id} claim with
 * a fallback to the legacy {@code tenantId} claim for backwards
 * compatibility with tokens issued before the canonical claim was
 * standardized.</p>
 */
public final class JwtTenantResolver {

    private JwtTenantResolver() {
    }

    /**
     * Extracts the tenant identifier from the given JWT.
     *
     * @param jwt the authenticated JWT token
     * @return the tenant ID string, or {@code null} if neither claim is present
     */
    public static String extractTenantId(Jwt jwt) {
        String tenantId = jwt.getClaimAsString("tenant_id");
        if (tenantId == null) {
            tenantId = jwt.getClaimAsString("tenantId");
        }
        return tenantId;
    }
}
