package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.infrastructure.network.origin.OriginFirewallFilter;
import io.github.brenomega.authkit.infrastructure.network.RequestIdFilter;
import io.github.brenomega.authkit.infrastructure.network.DuplicateParameterFilter;
import io.github.brenomega.authkit.infrastructure.network.rateLimit.EndpointAbuseRateLimitingFilter;
import io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter;

import io.github.brenomega.authkit.response.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Defines the stateless HTTP security boundary and the order of security filters.
 *
 * <p>The origin firewall and correlation checks run before request processing;
 * duplicate-parameter, layered rate-limit, endpoint-abuse, and body-size controls
 * precede application authentication. Worker authentication and live first-party
 * session/authority reconciliation run after bearer decoding. Routes not explicitly
 * classified are denied.</p>
 *
 * <p>Spring's session and CSRF mechanisms are disabled because access tokens are
 * stateless and refresh credentials use the controller's cookie-scoped double-submit
 * CSRF protocol. CORS and defensive response headers remain centrally configured.</p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final OriginFirewallFilter originFirewallFilter;
    private final RateLimitingFilter rateLimitingFilter;
    private final EndpointAbuseRateLimitingFilter endpointAbuseRateLimitingFilter;
    private final WorkerAuthFilter workerAuthFilter;
    private final RequestBodySizeLimitFilter requestBodySizeLimitFilter;
    private final RequestIdFilter requestIdFilter;
    private final DuplicateParameterFilter duplicateParameterFilter;
    private final AuthProperties authProperties;

    public SecurityConfig(
            ObjectMapper objectMapper,
            UserAuthoritiesFilter userAuthoritiesFilter,
            OriginFirewallFilter originFirewallFilter,
            RateLimitingFilter rateLimitingFilter,
            EndpointAbuseRateLimitingFilter endpointAbuseRateLimitingFilter,
            WorkerAuthFilter workerAuthFilter,
            RequestBodySizeLimitFilter requestBodySizeLimitFilter,
            RequestIdFilter requestIdFilter,
            DuplicateParameterFilter duplicateParameterFilter,
            AuthProperties authProperties) {
        this.objectMapper = objectMapper;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.originFirewallFilter = originFirewallFilter;
        this.rateLimitingFilter = rateLimitingFilter;
        this.endpointAbuseRateLimitingFilter = endpointAbuseRateLimitingFilter;
        this.workerAuthFilter = workerAuthFilter;
        this.requestBodySizeLimitFilter = requestBodySizeLimitFilter;
        this.requestIdFilter = requestIdFilter;
        this.duplicateParameterFilter = duplicateParameterFilter;
        this.authProperties = authProperties;
    }

    /** Builds the ordered filter chain and fail-closed authorization map. */
    @SuppressWarnings("null")
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
        http

            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> {})

            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .headers(headers -> headers
                .contentTypeOptions(cto -> {})
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .preload(true)
                        .maxAgeInSeconds(31536000))
                .referrerPolicy(referrer -> referrer
                        .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; " +
                            "form-action 'none'"))
            )

            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/social/*/start").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/v1/auth/social/*/callback").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/mfa/verify-login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/options").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/verify").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/logout").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/logout-all").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/email-confirmation/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/email-change/confirm").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/password-recovery/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/oauth2/token").permitAll()
                .requestMatchers(HttpMethod.GET, "/oauth2/authorize").permitAll()
                .requestMatchers(HttpMethod.POST, "/oauth2/revoke", "/oauth2/introspect").permitAll()
                .requestMatchers(HttpMethod.GET, "/oauth2/userinfo").permitAll()
                .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json", "/.well-known/**").permitAll()
                .requestMatchers("/api/v1/internal/**").hasRole("WORKER")
                .requestMatchers("/api/v1/admin/**").hasRole("PLATFORM_ADMIN")
                .requestMatchers("/api/v1/oauth2/**").authenticated()
                .requestMatchers("/api/v1/users/me", "/api/v1/users/me/**").hasAnyRole("USER", "PLATFORM_ADMIN")
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/prometheus").hasRole("WORKER")
                .anyRequest().denyAll()
            )

            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
                .bearerTokenResolver(request -> "/oauth2/userinfo".equals(request.getRequestURI())
                        ? null : bearerTokenResolver.resolve(request))
                .authenticationEntryPoint(this::handleAuthenticationError)
                .accessDeniedHandler(this::handleAccessDenied)
            )

            .addFilterBefore(originFirewallFilter, DisableEncodeUrlFilter.class)
            .addFilterBefore(requestIdFilter, OriginFirewallFilter.class)
            .addFilterAfter(duplicateParameterFilter, OriginFirewallFilter.class)

            .addFilterBefore(rateLimitingFilter, BearerTokenAuthenticationFilter.class)

            .addFilterAfter(endpointAbuseRateLimitingFilter, RateLimitingFilter.class)

            .addFilterBefore(requestBodySizeLimitFilter, BearerTokenAuthenticationFilter.class)

            .addFilterBefore(new TokenStateAvailabilityFilter(objectMapper), BearerTokenAuthenticationFilter.class)

            .addFilterAfter(workerAuthFilter, BearerTokenAuthenticationFilter.class)

            .addFilterAfter(userAuthoritiesFilter, WorkerAuthFilter.class);

        return http.build();
    }

    /** Builds credential-aware CORS policy from explicitly configured origins and headers. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        var cors = authProperties.getCors();
        if (cors.isEnabled()) {
            configuration.setAllowedOrigins(splitCsv(cors.getAllowedOrigins()));
            configuration.setAllowedMethods(splitCsv(cors.getAllowedMethods()));
            configuration.setAllowedHeaders(splitCsv(cors.getAllowedHeaders()));
            configuration.setExposedHeaders(splitCsv(cors.getExposedHeaders()));
            configuration.setAllowCredentials(cors.isAllowCredentials());
            configuration.setMaxAge(cors.getMaxAgeSeconds());
        }
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @SuppressWarnings("null")
    private List<String> splitCsv(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .toList();
    }

    private void handleAuthenticationError(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.AuthenticationException ex) throws IOException {

        writeErrorResponse(response, HttpStatus.UNAUTHORIZED, "Unauthorized");
    }

    private void handleAccessDenied(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.access.AccessDeniedException ex) throws IOException {

        writeErrorResponse(response, HttpStatus.FORBIDDEN, "Forbidden");
    }

    private void writeErrorResponse(
            HttpServletResponse response, HttpStatus status, String message) throws IOException {

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        if (status == HttpStatus.UNAUTHORIZED) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"authkit\"");
        }

        ApiResponse<Void> body = ApiResponse.error(
                status == HttpStatus.UNAUTHORIZED ? "unauthorized" : "forbidden", message);

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
