package io.github.brenomega.authkit.service.spi;

import java.util.List;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;

/**
 * Performs the provider-facing portion of a social OpenID Connect ceremony.
 *
 * <p>Implementations must reject discovery metadata whose issuer differs from
 * the configured provider and must accept only secure provider endpoints. Token
 * exchange must validate the ID token signature, issuer, audience, expiry and
 * expected nonce before returning identity claims. Failures are represented as
 * {@link io.github.brenomega.authkit.exception.InvalidSocialLoginException} so
 * callers do not expose provider-specific details.</p>
 */
public interface SocialOidcClient {

    /** Resolves and validates the configured provider's discovery metadata. */
    OidcProviderMetadata metadata(SocialIdentityProvider provider);

    /**
     * Exchanges a one-time authorization code and returns only verified claims.
     *
     * @param codeVerifier PKCE verifier associated with the initiating transaction
     * @param expectedNonce nonce bound to the initiating transaction
     */
    FederatedIdentity exchangeAndVerify(SocialIdentityProvider provider, String code, String codeVerifier,
                                        String redirectUri, String expectedNonce);

    /** Contains trusted endpoints obtained from validated discovery metadata. */
    record OidcProviderMetadata(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri) {}

    /** Contains identity claims extracted from a fully validated ID token. */
    record FederatedIdentity(String issuer, String subject, String email, boolean emailVerified,
                             String displayName, String acr, List<String> amr) {}
}
