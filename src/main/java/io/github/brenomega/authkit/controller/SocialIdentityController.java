package io.github.brenomega.authkit.controller;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.social.dto.SocialAuthorizationResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialIdentityResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.SocialIdentityService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/users/me/social-identities")
public class SocialIdentityController {
    private final SocialIdentityService service;
    public SocialIdentityController(SocialIdentityService service) { this.service = service; }

    @GetMapping
    public ApiResponse<List<SocialIdentityResponse>> list(@AuthenticationPrincipal Jwt jwt) {
        return new ApiResponse<>(service.list(UUID.fromString(jwt.getSubject())), null, Instant.now());
    }

    @PostMapping("/{providerKey}/link/start")
    public ApiResponse<SocialAuthorizationResponse> startLink(@AuthenticationPrincipal Jwt jwt,
            @PathVariable String providerKey, @Valid @RequestBody(required = false) StepUpRequest request) {
        return ApiResponse.success(service.startLink(providerKey, jwt, request));
    }

    @DeleteMapping("/{identityId}")
    public ApiResponse<String> unlink(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID identityId,
            @Valid @RequestBody(required = false) StepUpRequest request) {
        service.unlink(UUID.fromString(jwt.getSubject()), identityId, jwt, request);
        return ApiResponse.success("Social identity unlinked successfully.");
    }
}
