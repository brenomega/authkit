package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class UserAuthoritiesFilterTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Authority lookup is cached for the configured short TTL")
    void doFilterInternal_cachesUserAuthorityLookup() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry());
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = mock(User.class);

        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEmailConfirmed()).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());

        verify(userRepository, times(1)).findById(userId);
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Unconfirmed users are rejected before authorities are granted")
    void doFilterInternal_rejectsUnconfirmedUser() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry());
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = mock(User.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEmailConfirmed()).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Inactive server-side session rejects otherwise valid access token")
    void doFilterInternal_rejectsRevokedAccessTokenSession() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry());
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(false);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        verify(userRepository, times(0)).findById(userId);
    }

    private Jwt jwt(UUID userId, String jti) {
        Instant now = Instant.now();
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of("sub", userId.toString(), "jti", jti,
                        "aud", java.util.List.of("authkit-api"),
                        "token_use", JwtTokenUse.FIRST_PARTY_ACCESS,
                        "tenant_id", UUID.randomUUID().toString()));
    }

    private ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }
}
