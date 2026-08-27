package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.response.ApiResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Rejects duplicate query and form keys before controller binding can collapse them. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class DuplicateParameterFilter extends OncePerRequestFilter {
    private final ObjectMapper objectMapper;

    public DuplicateParameterFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String duplicate = request.getParameterMap().entrySet().stream()
                .filter(entry -> entry.getValue() != null && entry.getValue().length > 1)
                .map(Map.Entry::getKey)
                .findFirst().orElse(null);
        if (duplicate == null) {
            filterChain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        if (request.getRequestURI().startsWith("/oauth2/")) {
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "error", "invalid_request",
                    "error_description", "Duplicate parameter is not allowed"));
        } else {
            objectMapper.writeValue(response.getWriter(),
                    ApiResponse.error("duplicate_parameter", "Duplicate parameter is not allowed"));
        }
    }
}
