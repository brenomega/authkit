package io.github.brenomega.authkit.controller;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUserResponse;
import io.github.brenomega.authkit.domain.user.dto.MfaOptionalVerificationRequest;
import io.github.brenomega.authkit.domain.user.dto.TenantSummaryResponse;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AdminService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasAnyRole('ADMIN', 'TENANT_ADMIN')")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    @GetMapping("/users")
    public ApiResponse<List<AdminUserResponse>> listUsers(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue = "100") int limit) {
        return new ApiResponse<>(adminService.listUsers(jwt, limit), null, Instant.now());
    }

    @PatchMapping("/users/{userId}/role")
    public ApiResponse<AdminUserResponse> updateRole(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminUpdateRoleRequest request) {
        return new ApiResponse<>(adminService.updateRole(jwt, userId, request), null, Instant.now());
    }

    @GetMapping("/tenants")
    public ApiResponse<List<TenantSummaryResponse>> listTenants(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue = "100") int limit) {
        return new ApiResponse<>(adminService.listTenants(jwt, limit), null, Instant.now());
    }

    @GetMapping("/oauth-clients")
    public ApiResponse<List<AdminOAuthClientResponse>> listOAuthClients(@AuthenticationPrincipal Jwt jwt) {
        return new ApiResponse<>(adminService.listOAuthClients(jwt), null, Instant.now());
    }

    @PostMapping("/oauth-clients")
    public ApiResponse<AdminOAuthClientResponse> createOAuthClient(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody AdminOAuthClientCreateRequest request) {
        return new ApiResponse<>(adminService.createOAuthClient(jwt, request), null, Instant.now());
    }

    @PatchMapping("/oauth-clients/{clientId}")
    public ApiResponse<AdminOAuthClientResponse> updateOAuthClient(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID clientId,
            @Valid @RequestBody AdminOAuthClientUpdateRequest request) {
        return new ApiResponse<>(adminService.updateOAuthClient(jwt, clientId, request), null, Instant.now());
    }

    @DeleteMapping("/oauth-clients/{clientId}")
    public ApiResponse<String> disableOAuthClient(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID clientId,
            @Valid @RequestBody(required = false) MfaOptionalVerificationRequest request) {
        adminService.disableOAuthClient(
                jwt,
                clientId,
                request == null ? null : request.currentPassword(),
                request == null ? null : request.code());
        return new ApiResponse<>("OAuth client disabled successfully.", null, Instant.now());
    }
}
