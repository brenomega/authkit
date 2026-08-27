package io.github.brenomega.authkit.service.spi;

import java.util.List;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;

public interface SocialOidcClient {
    OidcProviderMetadata metadata(SocialIdentityProvider provider);
    FederatedIdentity exchangeAndVerify(SocialIdentityProvider provider, String code, String codeVerifier,
                                        String redirectUri, String expectedNonce);

    record OidcProviderMetadata(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri) {}
    record FederatedIdentity(String issuer, String subject, String email, boolean emailVerified,
                             String displayName, String acr, List<String> amr) {}
}
