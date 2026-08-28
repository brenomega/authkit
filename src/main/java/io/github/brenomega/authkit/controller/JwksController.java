package io.github.brenomega.authkit.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.infrastructure.security.JwtKeyService;

/** Publishes active and retiring JWT verification keys after revoked key IDs are removed. */
@RestController
public class JwksController {

    private final JwtKeyService jwtKeyService;

    public JwksController(JwtKeyService jwtKeyService) {
        this.jwtKeyService = jwtKeyService;
    }

    /** Returns public verification material only; the active private key never enters this boundary. */
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return jwtKeyService.publishedPublicJwkSet().toJSONObject();
    }
}
