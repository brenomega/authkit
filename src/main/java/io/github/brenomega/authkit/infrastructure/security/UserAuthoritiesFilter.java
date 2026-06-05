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
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter enforcing immediate permission revocation (DT 3.2.10).
 *
 * <p>By design, JWT claims represent the user's roles at the exact timestamp
 * of issuance. To guarantee immediate restriction on compromised or suspended roles
 * without waiting for the token to expire, this filter intercepts the request,
 * fetches the active roles natively from the DB, and overwrites the active context.</p>
 */
@Component
public class UserAuthoritiesFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final TokenStorage tokenStorage;
    private final ObjectMapper objectMapper;
    private final String apiAudience;
    private final Cache<UUID, Optional<CachedUserAuthorities>> authorityCache;

    public UserAuthoritiesFilter(
            UserRepository userRepository,
            TokenStorage tokenStorage,
            ObjectMapper objectMapper,
            AuthProperties authProperties,
            MeterRegistry meterRegistry) {
        this.userRepository = userRepository;
        this.tokenStorage = tokenStorage;
        this.objectMapper = objectMapper;
        this.apiAudience = authProperties.getJwt().getAudience();
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
            if (jti == null || jti.isBlank() || !tokenStorage.isSessionActive(userId.toString(), jti)) {
                SecurityContextHolder.clearContext();
                reject(response);
                return;
            }

            Optional<CachedUserAuthorities> cachedAuthorities =
                    authorityCache.get(userId, this::loadAuthorities);

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

    public void evict(UUID userId) {
        authorityCache.invalidate(userId);
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.error("Unauthorized"));
    }

    private record CachedUserAuthorities(
            Collection<? extends GrantedAuthority> authorities,
            boolean enabled) {
    }
}
