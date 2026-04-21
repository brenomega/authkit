package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.time.Instant;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.response.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Central Spring Security configuration (DT 3.2.5-3.2.8, DT 3.2.14).
 *
 * <p>Configures the application as a stateless OAuth2 Resource Server
 * that validates Bearer Tokens via JWT. Key characteristics:</p>
 * <ul>
 *   <li>Session management: {@code STATELESS} (DT 3.2.5)</li>
 *   <li>CSRF: disabled for Bearer Token API (DT 3.2.6)</li>
 *   <li>Method-level security: enabled via {@code @PreAuthorize} (DT 3.2.8)</li>
 *   <li>Security headers: {@code nosniff}, {@code DENY} (DT 3.2.14)</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper Jackson mapper for serializing error responses
     */
    public SecurityConfig(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Defines the security filter chain for the application.
     *
     * @param http the {@link HttpSecurity} builder
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // DT 3.2.6 — CSRF disabled for stateless Bearer Token API
            .csrf(csrf -> csrf.disable())

            // DT 3.2.5 — No HTTP sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // DT 3.2.14 — Security headers
            .headers(headers -> headers
                .contentTypeOptions(cto -> {})          // X-Content-Type-Options: nosniff
                .frameOptions(fo -> fo.deny())          // X-Frame-Options: DENY
            )

            // DT 3.2.8 — Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                .anyRequest().authenticated()
            )

            // DT 3.2.7 — OAuth2 Resource Server with JWT validation
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
                .authenticationEntryPoint(this::handleAuthenticationError)
                .accessDeniedHandler(this::handleAccessDenied)
            );

        return http.build();
    }

    /**
     * Handles authentication failures (missing/invalid/expired token).
     *
     * <p>Returns HTTP 401 with an {@link ApiResponse} envelope (DT 3.4.3).</p>
     */
    private void handleAuthenticationError(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.AuthenticationException ex) throws IOException {

        writeErrorResponse(response, HttpStatus.UNAUTHORIZED, "Unauthorized");
    }

    /**
     * Handles authorization failures (insufficient permissions).
     *
     * <p>Returns HTTP 403 with an {@link ApiResponse} envelope (DT 3.4.3).</p>
     */
    private void handleAccessDenied(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.access.AccessDeniedException ex) throws IOException {

        writeErrorResponse(response, HttpStatus.FORBIDDEN, "Forbidden");
    }

    /**
     * Writes a JSON error response wrapped in the {@link ApiResponse} envelope.
     *
     * @param response   the servlet response
     * @param status     the HTTP status code
     * @param message    the error message
     * @throws IOException if writing fails
     */
    private void writeErrorResponse(
            HttpServletResponse response, HttpStatus status, String message) throws IOException {

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiResponse<Void> body = new ApiResponse<>(null,
                java.util.List.of(message), Instant.now());

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
