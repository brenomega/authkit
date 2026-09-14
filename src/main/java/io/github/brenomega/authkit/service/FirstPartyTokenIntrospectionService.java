package io.github.brenomega.authkit.service;

import java.util.UUID;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import io.github.brenomega.authkit.domain.user.dto.FirstPartyIntrospectionResponse;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.JwtTokenUse;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Determines whether a first-party access token is still usable by AuthKit.
 *
 * <p>Cryptographic JWT validation alone is insufficient: the token must carry
 * the first-party token-use marker and configured audience, its account must
 * remain active and confirmed, its {@code jti}-bound server-side session must
 * still exist, and its durable PostgreSQL security version must still be accepted.
 * Every malformed, foreign, revoked or inactive token collapses to the same
 * inactive response.</p>
 */
@Service
public class FirstPartyTokenIntrospectionService {

    private final JwtDecoder jwtDecoder;
    private final TokenStorage tokenStorage;
    private final UserRepository userRepository;
    private final String audience;

    public FirstPartyTokenIntrospectionService(JwtDecoder jwtDecoder,
                                               TokenStorage tokenStorage,
                                               UserRepository userRepository,
                                               AuthProperties authProperties) {
        this.jwtDecoder = jwtDecoder;
        this.tokenStorage = tokenStorage;
        this.userRepository = userRepository;
        this.audience = authProperties.getJwt().getAudience();
    }

    /**
     * Introspects without exposing why an invalid token is inactive.
     *
     * @return active claims for a live first-party session, otherwise the common
     *         inactive representation
     */
    @SuppressWarnings("null")
    public FirstPartyIntrospectionResponse introspect(String rawToken) {
        try {
            Jwt jwt = jwtDecoder.decode(rawToken);
            if (!JwtTokenUse.isFirstPartyAccess(jwt, audience)
                    || jwt.getId() == null || jwt.getId().isBlank()) {
                return FirstPartyIntrospectionResponse.inactive();
            }
            UUID userId = UUID.fromString(jwt.getSubject());
            Object rawSessionVersion = jwt.getClaim("session_version");
            if (!(rawSessionVersion instanceof Number sessionVersion)) {
                return FirstPartyIntrospectionResponse.inactive();
            }
            boolean activeUser = userRepository.findById(userId)
                    .map(user -> user.isActive() && user.isEmailConfirmed()
                            && user.acceptsSession(jwt.getId(), sessionVersion.longValue()))
                    .orElse(false);
            if (!activeUser || !tokenStorage.isSessionActive(jwt.getSubject(), jwt.getId())) {
                return FirstPartyIntrospectionResponse.inactive();
            }
            return new FirstPartyIntrospectionResponse(
                    true,
                    jwt.getSubject(),
                    jwt.getClaimAsString("tenant_id"),
                    jwt.getExpiresAt(),
                    JwtTokenUse.FIRST_PARTY_ACCESS,
                    jwt.getClaimAsStringList("amr"));
        } catch (JwtException | IllegalArgumentException ex) {
            return FirstPartyIntrospectionResponse.inactive();
        }
    }
}
