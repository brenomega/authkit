package io.github.brenomega.authkit.controller;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.ProfileService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final ProfileService profileService;

    public UserController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @PutMapping("/{id}/profile")
    public ResponseEntity<ApiResponse<ProfileResponse>> updateProfile(
            @PathVariable("id") String id,
            @Valid @RequestBody ProfileUpdateRequest request,
            Principal principal) {
        
        // principal.getName() extracts the 'sub' claim from the standard Jwt token via BearerTokenAuthenticationFilter
        User updated = profileService.updateProfile(id, request, principal.getName());
        
        ProfileResponse responseDto = new ProfileResponse(
                updated.getId(),
                updated.getEmail(),
                updated.getName(),
                updated.getPhone()
        );

        return ResponseEntity.ok(ApiResponse.success(responseDto));
    }
}
