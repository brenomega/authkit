package io.github.brenomega.authkit.controller;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.JwtConfig;

/**
 * Controller exposing the JSON Web Key Set (JWKS) (DT 3.2.6).
 *
 * <p>Allows downstream services to fetch the active public keys for
 * stateless signature verification.</p>
 */
@RestController
public class JwksController {

    private final JwtConfig jwtConfig;
    private final AuthProperties authProperties;

    public JwksController(JwtConfig jwtConfig, AuthProperties authProperties) {
        this.jwtConfig = jwtConfig;
        this.authProperties = authProperties;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        RSAPublicKey publicKey = jwtConfig.getPublicKey();
        RSAKey jwk = new RSAKey.Builder(publicKey)
                .keyID(authProperties.getJwt().getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new JWKSet(jwk).toJSONObject();
    }
}
