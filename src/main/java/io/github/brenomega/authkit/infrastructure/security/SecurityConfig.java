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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.DisableEncodeUrlFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.infrastructure.network.origin.OriginFirewallFilter;
import io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter;

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
 *   <li>Security headers: {@code nosniff}, {@code DENY}, HSTS, CSP (DT 3.2.14)</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final OriginFirewallFilter originFirewallFilter;
    private final RateLimitingFilter rateLimitingFilter;
    private final WorkerAuthFilter workerAuthFilter;
    private final RequestBodySizeLimitFilter requestBodySizeLimitFilter;

    /**
     * @param objectMapper Jackson mapper for serializing error responses
     * @param userAuthoritiesFilter Dynamic authority enforcement filter
     * @param originFirewallFilter Origin TCP blocking bound wrapper (DT 3.2.19)
     * @param rateLimitingFilter Volumetric capacity restriction block
     */
    public SecurityConfig(
            ObjectMapper objectMapper, 
            UserAuthoritiesFilter userAuthoritiesFilter,
            OriginFirewallFilter originFirewallFilter,
            RateLimitingFilter rateLimitingFilter,
            WorkerAuthFilter workerAuthFilter,
            RequestBodySizeLimitFilter requestBodySizeLimitFilter) {
        this.objectMapper = objectMapper;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.originFirewallFilter = originFirewallFilter;
        this.rateLimitingFilter = rateLimitingFilter;
        this.workerAuthFilter = workerAuthFilter;
        this.requestBodySizeLimitFilter = requestBodySizeLimitFilter;
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
            .csrf(AbstractHttpConfigurer::disable)

            // DT 3.2.5 — No HTTP sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // DT 3.2.14 — Security headers
            .headers(headers -> headers
                .contentTypeOptions(cto -> {})          // X-Content-Type-Options: nosniff
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)          // X-Frame-Options: DENY
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .preload(true)
                        .maxAgeInSeconds(31536000))
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"))
            )

            // DT 3.2.8 — Authorization rules (Enforcing Deny-by-Default pattern)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/verify-login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/options").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/verify").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/logout").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/logout-all").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/email-confirmation/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/password-recovery/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/oauth2/token").permitAll()
                .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json", "/.well-known/**").permitAll()
                .requestMatchers("/api/v1/internal/**").hasRole("WORKER")
                .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN", "TENANT_ADMIN")
                .requestMatchers("/api/v1/oauth2/**").authenticated()
                .requestMatchers("/api/v1/users/me", "/api/v1/users/me/**").hasAnyRole("USER", "OWNER", "TENANT_ADMIN", "ADMIN")
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/prometheus").hasRole("WORKER")
                .anyRequest().denyAll()
            )

            // DT 3.2.7 — OAuth2 Resource Server with JWT validation
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
                .authenticationEntryPoint(this::handleAuthenticationError)
                .accessDeniedHandler(this::handleAccessDenied)
            )

            // DT 3.2.19 — Firewall dropping untrusted direct origins
            .addFilterBefore(originFirewallFilter, DisableEncodeUrlFilter.class)

            // DT 3.2.21 — Bucket4j limit enforced prior to Auth decode extraction limits
            .addFilterBefore(rateLimitingFilter, BearerTokenAuthenticationFilter.class)

            // DT 3.1.30 — Reject oversized bodies before JSON parsing or password hashing.
            .addFilterAfter(requestBodySizeLimitFilter, RateLimitingFilter.class)

            // DT 3.2.11 — Worker Auth injection immediately after standard extraction
            .addFilterAfter(workerAuthFilter, BearerTokenAuthenticationFilter.class)

            // DT 3.2.10 — Immediate Permission Revocation via active snapshot alignment
            .addFilterAfter(userAuthoritiesFilter, WorkerAuthFilter.class);

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
