package io.github.brenomega.authkit.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.user.dto.FirstPartyIntrospectionRequest;
import io.github.brenomega.authkit.domain.user.dto.FirstPartyIntrospectionResponse;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.FirstPartyTokenIntrospectionService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/internal/tokens")
public class InternalTokenController {

    private final FirstPartyTokenIntrospectionService introspectionService;

    public InternalTokenController(FirstPartyTokenIntrospectionService introspectionService) {
        this.introspectionService = introspectionService;
    }

    @PostMapping("/introspect")
    public ResponseEntity<ApiResponse<FirstPartyIntrospectionResponse>> introspect(
            @Valid @RequestBody FirstPartyIntrospectionRequest request) {
        return ResponseEntity.ok(ApiResponse.success(introspectionService.introspect(request.token())));
    }
}
