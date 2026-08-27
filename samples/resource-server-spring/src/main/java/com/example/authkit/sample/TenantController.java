package com.example.authkit.sample;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TenantController {

    @GetMapping("/sample/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sub", jwt.getSubject());
        response.put("tenant_id", jwt.getClaimAsString("tenant_id"));
        response.put("client_id", jwt.getClaimAsString("client_id"));
        response.put("scope", jwt.getClaimAsString("scope"));
        response.put("token_use", jwt.getClaimAsString("token_use"));
        return response;
    }

    @PreAuthorize("hasAuthority('SCOPE_sample.read')")
    @GetMapping("/sample/protected")
    public Map<String, Object> protectedResource(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("subject", jwt.getSubject(), "authorizedBy", "sample.read");
    }
}
