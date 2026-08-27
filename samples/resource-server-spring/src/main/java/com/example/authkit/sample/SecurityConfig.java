package com.example.authkit.sample;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${AUTHKIT_ISSUER:http://localhost:8080}") String issuer,
            @Value("${AUTHKIT_JWKS_URI:http://localhost:8080/.well-known/jwks.json}") String jwksUri,
            @Value("${AUTHKIT_ACCEPTED_AUDIENCE:sample-resource-api}") String acceptedAudience,
            @Value("${AUTHKIT_ACCEPTED_TOKEN_USE:oauth_access}") String acceptedTokenUse) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        decoder.setJwtValidator(authKitValidator(issuer, acceptedAudience, acceptedTokenUse));
        return decoder;
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(SecurityConfig::authorities);
        return converter;
    }

    static OAuth2TokenValidator<Jwt> authKitValidator(
            String issuer,
            String acceptedAudience,
            String acceptedTokenUse) {
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", audience ->
                        audience != null && audience.contains(acceptedAudience)),
                new JwtClaimValidator<String>("token_use", acceptedTokenUse::equals));
    }

    private static Collection<GrantedAuthority> authorities(Jwt jwt) {
        java.util.LinkedHashSet<GrantedAuthority> authorities = new java.util.LinkedHashSet<>();
        String scope = jwt.getClaimAsString("scope");
        if (scope != null) {
            for (String value : scope.split("\\s+")) {
                if (!value.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + value));
                }
            }
        }
        // AuthKit's PLATFORM_ADMIN role authorizes the AuthKit control plane only.
        // Host-product authorization must use client scopes or its own policy data.
        return authorities;
    }

}
