package io.github.brenomega.authkit.infrastructure.security;

import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import java.security.interfaces.RSAPrivateKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JWT configuration that loads RSA keys and provides the decoder bean (DT 3.2.2).
 *
 * <p>The RSA public key is loaded from the path specified by the
 * {@code jwt.public.key} property. In production this is an external file
 * injected via environment variable; in tests it points to a classpath
 * resource.</p>
 */
@Configuration
public class JwtConfig {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private final AuthProperties authProperties;

    /**
     * @param publicKey the RSA public key loaded by Spring's resource resolver
     * @param privateKey the RSA private key loaded by Spring's resource resolver
     */
    public JwtConfig(
            @Value("${jwt.public.key}") RSAPublicKey publicKey,
            @Value("${jwt.private.key}") RSAPrivateKey privateKey,
            AuthProperties authProperties) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.authProperties = authProperties;
    }

    /**
     * Creates a {@link JwtDecoder} that verifies JWT signatures using RS256.
     *
     * <p>Used by the OAuth2 Resource Server filter to validate Bearer Tokens
     * on incoming requests (DT 3.2.7).</p>
     *
     * @return a Nimbus-backed JWT decoder
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        OAuth2TokenValidator<Jwt> validator =
                JwtValidators.createDefaultWithIssuer(authProperties.getJwt().getIssuer());
        decoder.setJwtValidator(validator);
        return decoder;
    }

    /**
     * Creates a {@link JwtEncoder} using both the Public and Private keys.
     *
     * <p>Used to actively issue Access Tokens with all encapsulated boundaries.</p>
     *
     * @return a Nimbus-backed JWT encoder
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }
}
