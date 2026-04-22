package io.github.brenomega.authkit.infrastructure.network;

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
    "network.security.cloudflare.ranges=8.8.8.8/32"
})
public class NetworkSecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Dynamic Config: Cloudflare Firewall Filter uses overridden IP ranges and rejects 127.0.0.1")
    void firewall_usesOverriddenRanges_andRejectsLocalhost() throws Exception {
        // With ranges=8.8.8.8/32, localhost (127.0.0.1) should be forbidden
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("127.0.0.1");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Dynamic Config: Cloudflare Firewall Filter accepts the overridden IP")
    void firewall_acceptsOverriddenIp() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("8.8.8.8");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                // It should bypass the firewall and hit the next filter/controller (which might return 400 due to empty body)
                .andExpect(status().isBadRequest());
    }
}
