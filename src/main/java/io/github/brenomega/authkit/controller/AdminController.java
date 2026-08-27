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

import io.github.brenomega.authkit.domain.mfa.dto.MfaOptionalVerificationRequest;
import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientResponse;
import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUserResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminUserPageResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminUserDetailResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminSecurityEventPageResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminOperationalStatusResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminAccountStateRequest;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderCreateRequest;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderResponse;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderUpdateRequest;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AdminService;
import io.github.brenomega.authkit.service.SocialProviderAdminService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('PLATFORM_ADMIN')")
public class AdminController {

    private final AdminService adminService;
    private final SocialProviderAdminService socialProviderAdminService;

    public AdminController(AdminService adminService, SocialProviderAdminService socialProviderAdminService) {
        this.adminService = adminService;
        this.socialProviderAdminService = socialProviderAdminService;
    }

    @GetMapping("/users")
    public ApiResponse<AdminUserPageResponse> listUsers(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(required = false) String cursor) {
        return ApiResponse.success(adminService.listUsers(jwt, search, limit, cursor));
    }

    @GetMapping("/users/{userId}")
    public ApiResponse<AdminUserDetailResponse> getUser(
            @AuthenticationPrincipal Jwt jwt, @PathVariable UUID userId) {
        return ApiResponse.success(adminService.getUser(jwt, userId));
    }

    @PostMapping("/users/{userId}/sessions/revoke")
    public ApiResponse<String> revokeAllUserSessions(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody MfaOptionalVerificationRequest request) {
        adminService.revokeAllUserSessions(jwt, userId, request.currentPassword(), request.code());
        return ApiResponse.success("All user sessions revoked successfully.");
    }

    @GetMapping("/security-events")
    public ApiResponse<AdminSecurityEventPageResponse> listSecurityEvents(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false) UUID userId,
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(required = false) String cursor) {
        return ApiResponse.success(adminService.listSecurityEvents(jwt, userId, limit, cursor));
    }

    @GetMapping("/operations")
    public ApiResponse<AdminOperationalStatusResponse> operationalStatus(@AuthenticationPrincipal Jwt jwt) {
        return ApiResponse.success(adminService.operationalStatus(jwt));
    }

    @PatchMapping("/users/{userId}/role")
    public ApiResponse<AdminUserResponse> updateRole(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminUpdateRoleRequest request) {
        return new ApiResponse<>(adminService.updateRole(jwt, userId, request), null, Instant.now());
    }

    @PostMapping("/users/{userId}/suspension")
    public ApiResponse<AdminUserResponse> suspendUser(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminAccountStateRequest request) {
        return new ApiResponse<>(adminService.suspendUser(jwt, userId, request), null, Instant.now());
    }

    @DeleteMapping("/users/{userId}/suspension")
    public ApiResponse<AdminUserResponse> reactivateUser(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminAccountStateRequest request) {
        return new ApiResponse<>(adminService.reactivateUser(jwt, userId, request), null, Instant.now());
    }

    @DeleteMapping("/users/{userId}/deletion")
    public ApiResponse<AdminUserResponse> cancelDeletion(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminAccountStateRequest request) {
        return new ApiResponse<>(adminService.cancelDeletion(jwt, userId, request), null, Instant.now());
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

    @GetMapping("/social-providers")
    public ApiResponse<List<AdminSocialProviderResponse>> listSocialProviders(@AuthenticationPrincipal Jwt jwt) {
        return ApiResponse.success(socialProviderAdminService.list(jwt));
    }

    @PostMapping("/social-providers")
    public ApiResponse<AdminSocialProviderResponse> createSocialProvider(@AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody AdminSocialProviderCreateRequest request) {
        return ApiResponse.success(socialProviderAdminService.create(jwt, request));
    }

    @PatchMapping("/social-providers/{providerId}")
    public ApiResponse<AdminSocialProviderResponse> updateSocialProvider(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID providerId, @Valid @RequestBody AdminSocialProviderUpdateRequest request) {
        return ApiResponse.success(socialProviderAdminService.update(jwt, providerId, request));
    }

    @DeleteMapping("/social-providers/{providerId}")
    public ApiResponse<String> disableSocialProvider(@AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID providerId, @Valid @RequestBody MfaOptionalVerificationRequest request) {
        socialProviderAdminService.disable(jwt, providerId, request.currentPassword(), request.code());
        return ApiResponse.success("Social provider disabled successfully.");
    }
}
