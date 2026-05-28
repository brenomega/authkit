package io.github.brenomega.authkit.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.infrastructure.security.JwtKeyService;

/**
 * Controller exposing the JSON Web Key Set (JWKS) (DT 3.2.6).
 *
 * <p>Allows downstream services to fetch the active public keys for
 * stateless signature verification.</p>
 */
@RestController
public class JwksController {

    private final JwtKeyService jwtKeyService;

    public JwksController(JwtKeyService jwtKeyService) {
        this.jwtKeyService = jwtKeyService;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return jwtKeyService.publishedPublicJwkSet().toJSONObject();
    }
}
