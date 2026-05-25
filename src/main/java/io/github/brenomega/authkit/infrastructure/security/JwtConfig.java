package io.github.brenomega.authkit.infrastructure.security;

import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JWT configuration that loads RSA keys and provides the decoder/encoder beans (DT 3.2.2).
 *
 * <p>Pins the JWT signature to RS256 with key ID (kid) and audience validation (DT 3.2.6).</p>
 */
@Configuration
public class JwtConfig {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private final AuthProperties authProperties;

    public JwtConfig(
            @Value("${jwt.public.key}") RSAPublicKey publicKey,
            @Value("${jwt.private.key}") RSAPrivateKey privateKey,
            AuthProperties authProperties) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.authProperties = authProperties;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Creates a {@link JwtDecoder} that verifies JWT signatures using RS256.
     * Enforces issuer and audience verification (DT 3.2.6, DT 3.2.7).
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        OAuth2TokenValidator<Jwt> defaultValidator =
                JwtValidators.createDefaultWithIssuer(authProperties.getJwt().getIssuer());

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(authProperties.getJwt().getAudience());

        OAuth2TokenValidator<Jwt> combinedValidator =
                new DelegatingOAuth2TokenValidator<>(defaultValidator, audienceValidator);

        decoder.setJwtValidator(combinedValidator);
        return decoder;
    }

    /**
     * Creates a {@link JwtEncoder} using both the Public and Private keys.
     * Associates a configured key ID for JWKS targeting.
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(authProperties.getJwt().getKeyId())
                .build();
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
}
