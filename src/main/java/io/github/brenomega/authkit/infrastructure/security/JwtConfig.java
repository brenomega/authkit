package io.github.brenomega.authkit.infrastructure.security;

import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

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

    /**
     * @param publicKey the RSA public key loaded by Spring's resource resolver
     */
    public JwtConfig(@Value("${jwt.public.key}") RSAPublicKey publicKey) {
        this.publicKey = publicKey;
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
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
}
