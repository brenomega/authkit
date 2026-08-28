package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionException;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.SessionMetadataFactory;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Binds first-party JWT authorization to current server-side account state.
 *
 * <p>The filter accepts only first-party token use and the configured API audience,
 * requires the JWT {@code jti} to identify an active refresh session, and replaces
 * authorities with the current database role. Authorities are cached for a short
 * configured TTL and explicitly evicted on known authorization transitions; the
 * guarantee is therefore bounded by that TTL for out-of-band database changes.</p>
 */
@Component
public class UserAuthoritiesFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(UserAuthoritiesFilter.class);

    private final UserRepository userRepository;
    private final TokenStorage tokenStorage;
    private final ObjectMapper objectMapper;
    private final String apiAudience;
    private final long lastSeenThrottleSeconds;
    private final SessionMetadataFactory sessionMetadataFactory;
    private final Cache<UUID, Optional<CachedUserAuthorities>> authorityCache;
    private final MeterRegistry meterRegistry;

    public UserAuthoritiesFilter(
            UserRepository userRepository,
            TokenStorage tokenStorage,
            ObjectMapper objectMapper,
            AuthProperties authProperties,
            MeterRegistry meterRegistry,
            SessionMetadataFactory sessionMetadataFactory) {
        this.userRepository = userRepository;
        this.tokenStorage = tokenStorage;
        this.objectMapper = objectMapper;
        this.apiAudience = authProperties.getJwt().getAudience();
        this.lastSeenThrottleSeconds = authProperties.getTokenStorage().getSessionLastSeenThrottleSeconds();
        this.sessionMetadataFactory = sessionMetadataFactory;
        this.meterRegistry = meterRegistry;
        this.authorityCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(authProperties.getAuthorityCache().getTtlSeconds()))
                .maximumSize(authProperties.getAuthorityCache().getMaxSize())
                .recordStats()
                .build();
        CaffeineCacheMetrics.monitor(meterRegistry, authorityCache, "authkit.authority_cache");
    }

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Evaluate instances that have passed through BearerTokenAuthenticationFilter
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            if (!JwtTokenUse.isFirstPartyAccess(jwtAuth.getToken(), apiAudience)) {
                SecurityContextHolder.clearContext();
                reject(response);
                return;
            }
            UUID userId;
            try {
                userId = UUID.fromString(jwtAuth.getName()); // Resolves to 'sub' claim
            } catch (IllegalArgumentException ex) {
                reject(response);
                return;
            }

            String jti = jwtAuth.getToken().getId();
            Optional<CachedUserAuthorities> cachedAuthorities;
            try {
                if (jti == null || jti.isBlank() || !tokenStorage.isSessionActive(userId.toString(), jti)) {
                    SecurityContextHolder.clearContext();
                    reject(response);
                    return;
                }
                tokenStorage.touchSession(userId.toString(), jti, java.time.Instant.now(),
                        sessionMetadataFactory.currentMaskedIp(), lastSeenThrottleSeconds);
                cachedAuthorities = authorityCache.get(userId, this::loadAuthorities);
            } catch (DataAccessException | TransactionException ex) {
                dependencyUnavailable(response, ex);
                return;
            }

            if (cachedAuthorities.isEmpty() || !cachedAuthorities.get().enabled()) {
                SecurityContextHolder.clearContext();
                reject(response);
                return;
            }

            // Overwrite the Security Context mapped authorities explicitly with the current DB snapshot.
            JwtAuthenticationToken updatedToken = new JwtAuthenticationToken(
                    jwtAuth.getToken(),
                    cachedAuthorities.get().authorities(),
                    jwtAuth.getName()
            );

            SecurityContextHolder.getContext().setAuthentication(updatedToken);
        }

        filterChain.doFilter(request, response);
    }

    private Optional<CachedUserAuthorities> loadAuthorities(@NonNull UUID userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    SecurityUser securityUser = new SecurityUser(user);
                    return new CachedUserAuthorities(securityUser.getAuthorities(), securityUser.isEnabled());
                });
    }

    /** Invalidates cached account activity and authorities after a known state change. */
    public void evict(UUID userId) {
        authorityCache.invalidate(userId);
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.error("Unauthorized"));
    }

    private void dependencyUnavailable(HttpServletResponse response, RuntimeException ex) throws IOException {
        SecurityContextHolder.clearContext();
        meterRegistry.counter("security.infrastructure.failure", "component", "live_authority").increment();
        log.error("Live session or authority dependency unavailable", ex);
        response.resetBuffer();
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(),
                ApiResponse.error("dependency_unavailable", "Service temporarily unavailable"));
    }

    private record CachedUserAuthorities(
            Collection<? extends GrantedAuthority> authorities,
            boolean enabled) {
    }
}
