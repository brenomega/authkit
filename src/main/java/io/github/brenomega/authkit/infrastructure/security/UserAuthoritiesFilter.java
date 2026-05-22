package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.repository.UserRepository;
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

    public UserAuthoritiesFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Evaluate instances that have passed through BearerTokenAuthenticationFilter
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            String userId = jwtAuth.getName(); // Resolves to 'sub' claim

            userRepository.findById(java.util.UUID.fromString(userId)).ifPresent(user -> {
                SecurityUser securityUser = new SecurityUser(user);

                // Overwrite the Security Context mapped authorities explicitly with the current DB snapshot
                JwtAuthenticationToken updatedToken = new JwtAuthenticationToken(
                        jwtAuth.getToken(),
                        securityUser.getAuthorities(),
                        jwtAuth.getName()
                );
                
                SecurityContextHolder.getContext().setAuthentication(updatedToken);
            });
        }

        filterChain.doFilter(request, response);
    }
}
