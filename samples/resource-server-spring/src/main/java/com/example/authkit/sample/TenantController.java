package com.example.authkit.sample;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

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

    @GetMapping("/sample/tenant/{tenantId}/profile")
    public Map<String, Object> tenantProfile(@PathVariable String tenantId, @AuthenticationPrincipal Jwt jwt) {
        requireTenant(tenantId, jwt);
        return Map.of("tenant_id", tenantId, "sub", jwt.getSubject());
    }

    @PreAuthorize("hasAuthority('SCOPE_admin') or hasAuthority('ROLE_ADMIN')")
    @GetMapping("/sample/admin/tenant/{tenantId}/users")
    public Map<String, Object> tenantUsers(@PathVariable String tenantId, @AuthenticationPrincipal Jwt jwt) {
        requireTenant(tenantId, jwt);
        return Map.of("tenant_id", tenantId, "users", java.util.List.of());
    }

    private void requireTenant(String tenantId, Jwt jwt) {
        String tokenTenant = jwt.getClaimAsString("tenant_id");
        if (tokenTenant == null || tokenTenant.isBlank() || !tenantId.equals(tokenTenant)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "tenant mismatch");
        }
    }
}
