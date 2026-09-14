package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.exception.TokenRevocationUnavailableException;
import io.github.brenomega.authkit.response.ApiResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Maps token-store outages raised before MVC to the fail-closed availability contract. */
final class TokenStateAvailabilityFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;

    TokenStateAvailabilityFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (TokenRevocationUnavailableException ex) {
            SecurityContextHolder.clearContext();
            if (response.isCommitted()) {
                throw ex;
            }
            response.resetBuffer();
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getOutputStream(),
                    ApiResponse.error("token_revocation_unavailable", ex.getMessage()));
        }
    }
}
