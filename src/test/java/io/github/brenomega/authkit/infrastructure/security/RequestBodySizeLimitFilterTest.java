package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;

class RequestBodySizeLimitFilterTest {

    @Test
    @DisplayName("Rejects oversized bodies even when Content-Length is unavailable")
    void doFilter_rejectsOversizedBodyWithoutContentLength() throws Exception {
        AuthProperties authProperties = new AuthProperties();
        authProperties.getRequest().setMaxBodyBytes(16);
        RequestBodySizeLimitFilter filter = new RequestBodySizeLimitFilter(authProperties, objectMapper());
        MockHttpServletRequest request = new UnknownLengthRequest("POST", "/api/v1/auth/login");
        request.setContent("12345678901234567".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("Oversized request must not reach downstream filters");
        });

        assertEquals(413, response.getStatus());
        assertTrue(response.getContentAsString().contains("Request body too large"));
    }

    @Test
    @DisplayName("Preserves request body for downstream consumers after size validation")
    void doFilter_preservesBodyForDownstreamConsumers() throws Exception {
        AuthProperties authProperties = new AuthProperties();
        authProperties.getRequest().setMaxBodyBytes(64);
        RequestBodySizeLimitFilter filter = new RequestBodySizeLimitFilter(authProperties, objectMapper());
        MockHttpServletRequest request = new UnknownLengthRequest("POST", "/api/v1/auth/login");
        request.setContent("{\"email\":\"a@example.com\"}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> downstreamBody = new AtomicReference<>();
        FilterChain chain = (servletRequest, servletResponse) ->
                downstreamBody.set(new String(servletRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8));

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertEquals("{\"email\":\"a@example.com\"}", downstreamBody.get());
    }

    private static class UnknownLengthRequest extends MockHttpServletRequest {

        UnknownLengthRequest(String method, String requestUri) {
            super(method, requestUri);
        }

        @Override
        public int getContentLength() {
            return -1;
        }

        @Override
        public long getContentLengthLong() {
            return -1;
        }
    }

    private ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }
}
