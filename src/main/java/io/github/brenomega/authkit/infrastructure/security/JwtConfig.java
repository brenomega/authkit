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
 * JWT configuration that loads RSA keys and provides the decoder/encoder beans (DT 3.2.2).
 *
 * <p>Pins the JWT signature to RS256 with key ID (kid) and audience validation (DT 3.2.6).</p>
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

    /**
     * Creates a {@link JwtDecoder} that verifies JWT signatures using RS256.
     * Enforces issuer and audience verification (DT 3.2.6, DT 3.2.7).
     */
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
        OAuth2TokenValidator<Jwt> tokenUseValidator = new FirstPartyTokenUseValidator(authProperties.getJwt().getAudience());
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

    /**
     * Creates a {@link JwtEncoder} using both the Public and Private keys.
     * Associates a configured key ID for JWKS targeting.
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = jwtKeyService.activePrivateJwk();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Custom token validator to enforce the 'aud' (audience) claim (DT 3.2.6).
     */
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

    private static class KeyRevocationValidator implements OAuth2TokenValidator<Jwt> {
        private final JwtKeyService jwtKeyService;

        private KeyRevocationValidator(JwtKeyService jwtKeyService) {
            this.jwtKeyService = jwtKeyService;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            Object kid = jwt.getHeaders().get("kid");
            if (kid instanceof String keyId && jwtKeyService.isRevokedKid(keyId)) {
                OAuth2Error error = new OAuth2Error("invalid_token", "JWT signing key has been revoked", null);
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
