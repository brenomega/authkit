package io.github.brenomega.authkit.infrastructure.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "network.security.trusted-origins.ranges=172.30.0.10/32",
    "network.security.worker-trusted-origins.ranges=172.30.0.20/32"
})
class IndependentNetworkBoundariesIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Public reverse proxy can reach public APIs but cannot satisfy worker network trust")
    void publicProxyIsNotAWorkerPeer() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("172.30.0.10");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/v1/internal/tokens/introspect")
                        .with(request -> {
                            request.setRemoteAddr("172.30.0.10");
                            return request;
                        })
                        .header("X-Worker-Token", "test-dummy-worker-token")
                        .contentType("application/json")
                        .content("{\"token\":\"not-a-jwt\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Worker endpoint requires both dedicated network peer and worker token")
    void workerRequiresNetworkAndToken() throws Exception {
        mockMvc.perform(post("/api/v1/internal/tokens/introspect")
                        .with(request -> {
                            request.setRemoteAddr("172.30.0.20");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{\"token\":\"not-a-jwt\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/internal/tokens/introspect")
                        .with(request -> {
                            request.setRemoteAddr("172.30.0.20");
                            return request;
                        })
                        .header("X-Worker-Token", "test-dummy-worker-token")
                        .contentType("application/json")
                        .content("{\"token\":\"not-a-jwt\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Worker peer cannot bypass the public reverse-proxy boundary")
    void workerPeerIsNotAPublicProxy() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("172.30.0.20");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isForbidden());
    }
}
