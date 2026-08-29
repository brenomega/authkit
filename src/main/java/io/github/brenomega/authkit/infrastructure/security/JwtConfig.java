package io.github.brenomega.authkit.infrastructure.security;

import java.security.interfaces.RSAPublicKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Configures distinct JWT signing and first-party resource-server verification boundaries.
 *
 * <p>The decoder accepts RS256 signatures from active or retiring published keys,
 * then requires issuer, API audience, first-party token-use shape, a key ID that is
 * not revoked, and a token JTI not known to be revoked. OAuth access tokens and ID
 * tokens therefore cannot be substituted for first-party API access even when
 * signed by the same key.</p>
 */
@Configuration
public class JwtConfig {

    private final JwtKeyService jwtKeyService;
    private final AuthProperties authProperties;
    private final OAuthTokenRevocationService tokenRevocationService;

    public JwtConfig(JwtKeyService jwtKeyService,
                     AuthProperties authProperties,
                     OAuthTokenRevocationService tokenRevocationService) {
        this.jwtKeyService = jwtKeyService;
        this.authProperties = authProperties;
        this.tokenRevocationService = tokenRevocationService;
    }

    public RSAPublicKey getPublicKey() {
        return jwtKeyService.activePublicKey();
    }

    /** Returns the decoder whose validators define acceptance for first-party API tokens. */
    @Bean
    public JwtDecoder jwtDecoder() {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(jwtKeyService.publishedPublicJwkSet()));
        jwtProcessor.setJWSKeySelector(keySelector);
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);

        OAuth2TokenValidator<Jwt> defaultValidator =
                JwtValidators.createDefaultWithIssuer(authProperties.getJwt().getIssuer());

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(authProperties.getJwt().getAudience());
        OAuth2TokenValidator<Jwt> tokenUseValidator =
                new FirstPartyTokenUseValidator(authProperties.getJwt().getAudience());
        OAuth2TokenValidator<Jwt> keyRevocationValidator = new KeyRevocationValidator(jwtKeyService);
        OAuth2TokenValidator<Jwt> tokenRevocationValidator = new TokenRevocationValidator(tokenRevocationService);

        OAuth2TokenValidator<Jwt> combinedValidator =
                new DelegatingOAuth2TokenValidator<>(
                        defaultValidator,
                        audienceValidator,
                        tokenUseValidator,
                        keyRevocationValidator,
                        tokenRevocationValidator);

        decoder.setJwtValidator(combinedValidator);
        return decoder;
    }

    private static class FirstPartyTokenUseValidator implements OAuth2TokenValidator<Jwt> {
        private final String apiAudience;

        private FirstPartyTokenUseValidator(String apiAudience) {
            this.apiAudience = apiAudience;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (JwtTokenUse.isFirstPartyAccess(jwt, apiAudience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Token is not a first-party access token", null));
        }
    }

    /** Returns an encoder backed only by the currently active private signing key. */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = jwtKeyService.activePrivateJwk();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    private static class AudienceValidator implements OAuth2TokenValidator<Jwt> {
        private final String audience;

        public AudienceValidator(String audience) {
            this.audience = audience;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (jwt.getAudience() != null && jwt.getAudience().contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }
            OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }

    static class KeyRevocationValidator implements OAuth2TokenValidator<Jwt> {
        private final JwtKeyService jwtKeyService;

        KeyRevocationValidator(JwtKeyService jwtKeyService) {
            this.jwtKeyService = jwtKeyService;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            Object kid = jwt.getHeaders().get("kid");
            if (!(kid instanceof String keyId) || keyId.isBlank() || !jwtKeyService.isPublishedKid(keyId)) {
                OAuth2Error error = new OAuth2Error(
                        "invalid_token", "JWT signing key ID is missing or not published", null);
                return OAuth2TokenValidatorResult.failure(error);
            }
            return OAuth2TokenValidatorResult.success();
        }
    }

    private static class TokenRevocationValidator implements OAuth2TokenValidator<Jwt> {
        private final OAuthTokenRevocationService tokenRevocationService;

        private TokenRevocationValidator(OAuthTokenRevocationService tokenRevocationService) {
            this.tokenRevocationService = tokenRevocationService;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (tokenRevocationService.isRevoked(jwt.getId())) {
                OAuth2Error error = new OAuth2Error("invalid_token", "JWT has been revoked", null);
                return OAuth2TokenValidatorResult.failure(error);
            }
            return OAuth2TokenValidatorResult.success();
        }
    }
}
