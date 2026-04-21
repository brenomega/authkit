package io.github.brenomega.authkit.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.dto.RegisterResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.RegistrationService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final RegistrationService registrationService;

    public AuthController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        
        User user = registrationService.registerUser(request);
        
        RegisterResponse responseDto = new RegisterResponse(
                user.getId(),
                user.getEmail(),
                user.getTenantId()
        );
        
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(responseDto));
    }
}
