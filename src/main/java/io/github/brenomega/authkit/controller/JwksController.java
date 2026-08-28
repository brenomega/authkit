package io.github.brenomega.authkit.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.infrastructure.security.JwtKeyService;

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
