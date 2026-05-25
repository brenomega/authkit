package io.github.brenomega.authkit;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import org.springframework.test.web.servlet.MvcResult;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.RegistrationService;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;
import jakarta.servlet.http.Cookie;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserRepository userRepository;

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
        registerConfirmed(registerRequest);

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
                .andExpect(cookie().secure("Refresh-Token", true))
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
                .andExpect(cookie().secure("XSRF-TOKEN", true));
    }

    @Test
    @DisplayName("Refresh rotates refresh token and rejects replay of the old cookie")
    void refresh_success_rotatesAndRejectsReplay() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(
                "refresh-flow@example.com",
                "SuperPassword123!",
                true,
                true
        );
        registerConfirmed(registerRequest);

        String payload = """
                {
                   "email": "refresh-flow@example.com",
                   "password": "SuperPassword123!"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("Refresh-Token"))
                .andReturn();

        Cookie originalCookie = loginResult.getResponse().getCookie("Refresh-Token");
        Cookie originalCsrfCookie = loginResult.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(originalCookie);
        assertNotNull(originalCsrfCookie);

        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(originalCookie, originalCsrfCookie)
                        .header("X-XSRF-TOKEN", originalCsrfCookie.getValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(cookie().exists("Refresh-Token"))
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andReturn();

        Cookie rotatedCookie = refreshResult.getResponse().getCookie("Refresh-Token");
        assertNotNull(rotatedCookie);
        assertNotEquals(originalCookie.getValue(), rotatedCookie.getValue());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(originalCookie, originalCsrfCookie)
                        .header("X-XSRF-TOKEN", originalCsrfCookie.getValue()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Refresh token reuse detected. All sessions revoked for your security."));
    }

    @Test
    @DisplayName("Refresh with cookie but without CSRF header is rejected")
    void refresh_missingCsrfHeader_returns403() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(
                "csrf-flow@example.com",
                "SuperPassword123!",
                true,
                true
        );
        registerConfirmed(registerRequest);

        String payload = """
                {
                   "email": "csrf-flow@example.com",
                   "password": "SuperPassword123!"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        Cookie refreshCookie = loginResult.getResponse().getCookie("Refresh-Token");
        Cookie csrfCookie = loginResult.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(refreshCookie);
        assertNotNull(csrfCookie);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(refreshCookie, csrfCookie))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errors[0]").value("Invalid CSRF token"));
    }

    @Test
    @DisplayName("Logout revokes current refresh-token-backed session and clears cookie")
    void logout_revokesSessionAndClearsCookie() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(
                "logout-flow@example.com",
                "SuperPassword123!",
                true,
                true
        );
        registerConfirmed(registerRequest);

        String payload = """
                {
                   "email": "logout-flow@example.com",
                   "password": "SuperPassword123!"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        Cookie refreshCookie = loginResult.getResponse().getCookie("Refresh-Token");
        Cookie csrfCookie = loginResult.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(refreshCookie);
        assertNotNull(csrfCookie);

        mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(refreshCookie, csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue()))
                .andExpect(status().isOk())
                .andExpect(cookie().maxAge("Refresh-Token", 0))
                .andExpect(cookie().maxAge("XSRF-TOKEN", 0));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(refreshCookie, csrfCookie)
                        .header("X-XSRF-TOKEN", csrfCookie.getValue()))
                .andExpect(status().isUnauthorized());
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

    @SuppressWarnings("null")
    @Test
    @DisplayName("Oversized login password is rejected before hashing")
    void login_oversizedPassword_returns400() throws Exception {
        String payload = """
                {
                   "email": "dos@example.com",
                   "password": "%s"
                }
                """.formatted("A".repeat(129));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isBadRequest());
    }

    private User registerConfirmed(RegisterRequest registerRequest) {
        User user = registrationService.registerUser(registerRequest);
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }
}
