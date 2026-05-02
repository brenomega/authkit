package io.github.brenomega.authkit.controller;

import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.SessionResponse;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.ProfileService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

/**
 * Controller for User Profile and Session Management (RF 2.1.6 - 2.1.8).
 * 
 * <p>All endpoints require authentication and are bounded to the 'me' context
 * to prevent IDOR vulnerabilities (DT 3.2.24).</p>
 */
@RestController
@RequestMapping("/api/v1/users/me")
public class UserController {

    private final ProfileService profileService;

    public UserController(ProfileService profileService) {
        this.profileService = profileService;
    }

    /**
     * Returns the authenticated user's profile information (RF 2.1.6).
     */
    @GetMapping
    public ApiResponse<ProfileResponse> getMyProfile(@AuthenticationPrincipal Jwt jwt) {
        ProfileResponse profile = profileService.getProfile(jwt.getSubject());
        return new ApiResponse<>(profile, null, Instant.now());
    }

    /**
     * Updates non-sensitive user data (RF 2.1.6).
     */
    @PatchMapping
    public ApiResponse<ProfileResponse> updateMyProfile(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ProfileUpdateRequest request) {
        ProfileResponse updated = profileService.updateProfile(jwt.getSubject(), request, jwt.getSubject());
        return new ApiResponse<>(updated, null, Instant.now());
    }

    /**
     * Changes the password while the user is authenticated (RF 2.1.7).
     * 
     * <p>Revokes all other sessions except the current one upon success.</p>
     */
    @PostMapping("/password")
    public ApiResponse<String> changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody PasswordChangeRequest request) {
        profileService.changePassword(jwt.getSubject(), request, jwt.getId());
        return new ApiResponse<>("Password changed successfully. All other sessions revoked.", null, Instant.now());
    }

    /**
     * Lists active refresh token sessions (RF 2.1.8).
     */
    @GetMapping("/sessions")
    public ApiResponse<List<SessionResponse>> getMySessions(@AuthenticationPrincipal Jwt jwt) {
        List<SessionResponse> sessions = profileService.listSessions(jwt.getSubject());
        return new ApiResponse<>(sessions, null, Instant.now());
    }

    /**
     * Revokes a specific session (RF 2.1.8).
     */
    @DeleteMapping("/sessions/{jti}")
    public ApiResponse<String> revokeSession(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable String jti) {
        profileService.revokeSession(jwt.getSubject(), jti);
        return new ApiResponse<>("Session revoked successfully.", null, Instant.now());
    }
}
