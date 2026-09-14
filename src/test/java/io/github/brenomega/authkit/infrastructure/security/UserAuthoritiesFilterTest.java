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
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.CannotCreateTransactionException;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.UserRepository.SessionSecurityState;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.service.SessionMetadataFactory;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class UserAuthoritiesFilterTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Authority lookup is cached for the configured short TTL")
    void doFilterInternal_cachesUserAuthorityLookup() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = mock(User.class);

        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isActive()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(0, null)));
        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());

        verify(userRepository, times(1)).findById(userId);
        verify(userRepository, times(2)).findSessionSecurityStateById(userId);
    }

    @Test
    @DisplayName("Unconfirmed users are rejected before authorities are granted")
    void doFilterInternal_rejectsUnconfirmedUser() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = mock(User.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEmailConfirmed()).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(0, null)));
        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("Inactive server-side session rejects otherwise valid access token")
    void doFilterInternal_rejectsRevokedAccessTokenSession() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = enabledUser();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(false);

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        verify(userRepository, times(0)).findById(userId);
    }

    @Test
    @DisplayName("Live authority dependency failure is an opaque fail-closed 503")
    void doFilterInternal_returns503WhenAuthorityStoreIsUnavailable() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(0, null)));
        when(userRepository.findById(userId))
                .thenThrow(new DataAccessResourceFailureException("database unavailable"));

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(503, response.getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(response.getContentAsString().contains("dependency_unavailable"));
        org.junit.jupiter.api.Assertions.assertFalse(response.getContentAsString().contains("database unavailable"));
    }

    @Test
    @DisplayName("Transaction acquisition failure in live authority lookup is an opaque 503")
    void doFilterInternal_returns503WhenAuthorityTransactionCannotStart() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(0, null)));
        when(userRepository.findById(userId))
                .thenThrow(new CannotCreateTransactionException("database unavailable"));

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(userId, jti)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(503, response.getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(response.getContentAsString().contains("dependency_unavailable"));
        org.junit.jupiter.api.Assertions.assertFalse(response.getContentAsString().contains("database unavailable"));
    }

    @Test
    @DisplayName("OAuth access tokens are rejected before first-party session lookup")
    void doFilterInternal_rejectsOAuthTokenClassBeforeSessionLookup() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        MockHttpServletResponse response = new MockHttpServletResponse();

        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt(
                    userId,
                    UUID.randomUUID().toString(),
                    JwtTokenUse.OAUTH_ACCESS,
                    "client-api")));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        verify(
            tokenStorage,
            times(0)).isSessionActive(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(userRepository, times(0)).findById(userId);
    }

    @Test
    @DisplayName("ID tokens are rejected before first-party session lookup")
    void doFilterInternal_rejectsIdTokenClassBeforeSessionLookup() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        AuthProperties authProperties = new AuthProperties();
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), authProperties, new SimpleMeterRegistry(),
                mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        MockHttpServletResponse response = new MockHttpServletResponse();

        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt(
                    userId,
                    UUID.randomUUID().toString(),
                    JwtTokenUse.ID_TOKEN,
                    "client-api")));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        verify(
            tokenStorage,
            times(0)).isSessionActive(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(userRepository, times(0)).findById(userId);
    }

    @Test
    @DisplayName("A stale security version is rejected even while Redis still has the session")
    void doFilterInternal_rejectsStaleSecurityVersion() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), new AuthProperties(),
                new SimpleMeterRegistry(), mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = enabledUser();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(2, null)));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt(userId, jti, 1)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("Legacy first-party token without a security version is rejected")
    void doFilterInternal_rejectsMissingSecurityVersion() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), new AuthProperties(),
                new SimpleMeterRegistry(), mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        MockHttpServletResponse response = new MockHttpServletResponse();
        User user = enabledUser();
        Instant now = Instant.now();
        Jwt legacyToken = new Jwt(
                "token", now, now.plusSeconds(300), Map.of("alg", "RS256"),
                Map.of("sub", userId.toString(), "jti", jti,
                        "aud", List.of("authkit-api"),
                        "token_use", JwtTokenUse.FIRST_PARTY_ACCESS,
                        "tenant_id", UUID.randomUUID().toString(),
                        "amr", List.of("pwd")));

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(0, null)));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(legacyToken));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("The explicitly preserved current session survives a version advance")
    void doFilterInternal_acceptsPreservedSession() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        TokenStorage tokenStorage = mock(TokenStorage.class);
        UserAuthoritiesFilter filter = new UserAuthoritiesFilter(
                userRepository, tokenStorage, objectMapper(), new AuthProperties(),
                new SimpleMeterRegistry(), mock(SessionMetadataFactory.class));
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = enabledUser();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(tokenStorage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(userRepository.findSessionSecurityStateById(userId))
                .thenReturn(Optional.of(sessionState(2, jti)));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt(userId, jti, 1)));
        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    private Jwt jwt(UUID userId, String jti) {
        return jwt(userId, jti, JwtTokenUse.FIRST_PARTY_ACCESS, "authkit-api");
    }

    private Jwt jwt(UUID userId, String jti, String tokenUse, String audience) {
        return jwt(userId, jti, tokenUse, audience, 0);
    }

    private Jwt jwt(UUID userId, String jti, long sessionVersion) {
        return jwt(userId, jti, JwtTokenUse.FIRST_PARTY_ACCESS, "authkit-api", sessionVersion);
    }

    private Jwt jwt(UUID userId, String jti, String tokenUse, String audience, long sessionVersion) {
        Instant now = Instant.now();
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of("sub", userId.toString(), "jti", jti,
                        "aud", List.of(audience),
                        "token_use", tokenUse,
                        "session_version", sessionVersion,
                        "tenant_id", UUID.randomUUID().toString(),
                        "amr", List.of("pwd")));
    }

    private SessionSecurityState sessionState(long version, String preservedJti) {
        return new SessionSecurityState() {
            @Override
            public long getSecurityVersion() {
                return version;
            }

            @Override
            public String getPreservedSessionJti() {
                return preservedJti;
            }
        };
    }

    private User enabledUser() {
        User user = mock(User.class);
        when(user.getRole()).thenReturn(Role.USER);
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isActive()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);
        return user;
    }

    private ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }
}
