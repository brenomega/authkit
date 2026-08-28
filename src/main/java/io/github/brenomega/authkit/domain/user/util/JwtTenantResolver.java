package io.github.brenomega.authkit.domain.user.util;

import org.springframework.security.oauth2.jwt.Jwt;

/** Extracts the tenant claim used by service authorization and persistence filtering. */
public final class JwtTenantResolver {

    private JwtTenantResolver() {
    }

    public static String extractTenantId(Jwt jwt) {
        String tenantId = jwt.getClaimAsString("tenant_id");
        if (tenantId == null) {
            tenantId = jwt.getClaimAsString("tenantId");
        }
        return tenantId;
    }
}
