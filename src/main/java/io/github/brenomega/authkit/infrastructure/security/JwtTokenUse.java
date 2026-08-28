package io.github.brenomega.authkit.infrastructure.security;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Classifies the distinct JWT types issued by AuthKit.
 *
 * <p>New tokens carry an explicit {@value #CLAIM}. Classification also accepts
 * legacy tokens without that claim when their audience and OAuth-only claims are
 * unambiguous. An ID token is never classified as an access token.</p>
 */
public final class JwtTokenUse {

    public static final String CLAIM = "token_use";
    public static final String FIRST_PARTY_ACCESS = "first_party_access";
    public static final String OAUTH_ACCESS = "oauth_access";
    public static final String ID_TOKEN = "id_token";

    private JwtTokenUse() {
    }

    /** Tests explicit or legacy first-party access-token shape for the API audience. */
    public static boolean isFirstPartyAccess(Jwt jwt, String apiAudience) {
        String tokenUse = jwt.getClaimAsString(CLAIM);
        if (FIRST_PARTY_ACCESS.equals(tokenUse)) {
            return hasAudience(jwt, apiAudience);
        }
        return tokenUse == null
                && hasAudience(jwt, apiAudience)
                && jwt.getClaimAsString("client_id") == null
                && jwt.getClaimAsString("scope") == null;
    }

    /** Tests explicit or legacy OAuth access-token shape with client and scope binding. */
    public static boolean isOAuthAccess(Jwt jwt) {
        String tokenUse = jwt.getClaimAsString(CLAIM);
        if (OAUTH_ACCESS.equals(tokenUse)) {
            return jwt.getClaimAsString("client_id") != null
                    && jwt.getClaimAsString("scope") != null;
        }
        return tokenUse == null
                && jwt.getClaimAsString("client_id") != null
                && jwt.getClaimAsString("scope") != null;
    }

    private static boolean hasAudience(Jwt jwt, String audience) {
        return jwt.getAudience() != null && jwt.getAudience().contains(audience);
    }
}
