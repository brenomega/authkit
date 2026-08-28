package io.github.brenomega.authkit.infrastructure.security;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Classifies JWTs by claim shape to prevent token substitution across trust boundaries.
 * Token-use checks supplement signature, issuer, expiry, audience, and revocation
 * validation; they do not perform those validations themselves.
 */
public final class JwtTokenUse {

    public static final String CLAIM = "token_use";
    public static final String FIRST_PARTY_ACCESS = "first_party_access";
    public static final String OAUTH_ACCESS = "oauth_access";
    public static final String ID_TOKEN = "id_token";

    private JwtTokenUse() {
    }

    /** Requires first-party use, the API audience, and absence of OAuth client and scope claims. */
    public static boolean isFirstPartyAccess(Jwt jwt, String apiAudience) {
        String tokenUse = jwt.getClaimAsString(CLAIM);
        return FIRST_PARTY_ACCESS.equals(tokenUse)
                && hasAudience(jwt, apiAudience)
                && jwt.getClaimAsString("client_id") == null
                && jwt.getClaimAsString("scope") == null;
    }

    /** Requires OAuth access use together with both client and scope claims. */
    public static boolean isOAuthAccess(Jwt jwt) {
        String tokenUse = jwt.getClaimAsString(CLAIM);
        return OAUTH_ACCESS.equals(tokenUse)
                && jwt.getClaimAsString("client_id") != null
                && jwt.getClaimAsString("scope") != null;
    }

    /** Requires ID-token use and rejects OAuth access-token claim shape. */
    public static boolean isIdToken(Jwt jwt) {
        return ID_TOKEN.equals(jwt.getClaimAsString(CLAIM))
                && jwt.getClaimAsString("client_id") == null
                && jwt.getClaimAsString("scope") == null;
    }

    private static boolean hasAudience(Jwt jwt, String audience) {
        return jwt.getAudience() != null && jwt.getAudience().contains(audience);
    }
}
