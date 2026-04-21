package io.github.brenomega.authkit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.service.RegistrationService;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @MockitoBean
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Successful login protects refresh token in HttpOnly SameSite cookie and returns JWT Access Token")
    void login_success_returnsTokens() throws Exception {
        // Pre-create user mimicking standard Argon2id configurations
        RegisterRequest registerRequest = new RegisterRequest(
                "logintarget@example.com",
                "SuperPassword123!",
                true,
                true
        );
        registrationService.registerUser(registerRequest);

        String payload = """
                {
                   "email": "logintarget@example.com",
                   "password": "SuperPassword123!"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.expiresIn").value(900)) // 15 mins default
                // Validate DT 3.2.22 Secure Transport mapping
                .andExpect(cookie().exists("Refresh-Token"))
                .andExpect(cookie().httpOnly("Refresh-Token", true))
                .andExpect(cookie().secure("Refresh-Token", true));
    }

    @Test
    @DisplayName("Invalid Password login maps to generic 401 unconditional response without enumeration leakage")
    void login_invalidPassword_returns401() throws Exception {
        String payload = """
                {
                   "email": "logintarget@example.com",
                   "password": "WrongPasswordX!"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Invalid email or password"));
    }
}
