package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

class FirstPartyTokenIntrospectionServiceTest {

    private JwtDecoder decoder;
    private TokenStorage storage;
    private UserRepository users;
    private FirstPartyTokenIntrospectionService service;

    @BeforeEach
    void setUp() {
        decoder = mock(JwtDecoder.class);
        storage = mock(TokenStorage.class);
        users = mock(UserRepository.class);
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setAudience("authkit-api");
        service = new FirstPartyTokenIntrospectionService(decoder, storage, users, properties);
    }

    @Test
    void activeOnlyWhenTokenClassUserAndLiveSessionAreValid() {
        UUID userId = UUID.randomUUID();
        String jti = UUID.randomUUID().toString();
        User user = mock(User.class);
        when(user.isActive()).thenReturn(true);
        when(user.isEmailConfirmed()).thenReturn(true);
        when(users.findById(userId)).thenReturn(Optional.of(user));
        when(storage.isSessionActive(userId.toString(), jti)).thenReturn(true);
        when(decoder.decode("valid")).thenReturn(jwt(userId, jti, "first_party_access", "authkit-api"));

        assertTrue(service.introspect("valid").active());

        when(storage.isSessionActive(userId.toString(), jti)).thenReturn(false);
        assertFalse(service.introspect("valid").active());
    }

    @Test
    void rejectsOAuthAndIdTokenClassesEvenWhenSigned() {
        UUID userId = UUID.randomUUID();
        when(decoder.decode("oauth")).thenReturn(jwt(userId, "oauth-jti", "oauth_access", "client-a"));
        when(decoder.decode("id")).thenReturn(jwt(userId, "id-jti", "id_token", "client-a"));

        assertFalse(service.introspect("oauth").active());
        assertFalse(service.introspect("id").active());
    }

    private Jwt jwt(UUID userId, String jti, String tokenUse, String audience) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(userId.toString())
                .claim("jti", jti)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .audience(List.of(audience))
                .claim("token_use", tokenUse);
        if ("oauth_access".equals(tokenUse)) {
            builder.claim("client_id", audience).claim("scope", "openid");
        }
        return builder.build();
    }
}
