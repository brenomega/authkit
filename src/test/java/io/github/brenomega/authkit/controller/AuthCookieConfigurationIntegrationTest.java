package io.github.brenomega.authkit.controller;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.service.RegistrationService;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;
import jakarta.servlet.http.Cookie;

@SpringBootTest(properties = {
        "authkit.auth.cookie.refresh-name=AuthKit-Refresh",
        "authkit.auth.cookie.path=/api/v1/auth",
        "authkit.auth.cookie.same-site=Lax"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthCookieConfigurationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @MockitoBean
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Configured refresh cookie name is used for login and refresh")
    void configuredRefreshCookieName_isUsedForLoginAndRefresh() throws Exception {
        registrationService.registerUser(new RegisterRequest(
                "custom-cookie@example.com",
                "SuperPassword123!",
                true,
                true
        ));

        String payload = """
                {
                   "email": "custom-cookie@example.com",
                   "password": "SuperPassword123!"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("AuthKit-Refresh"))
                .andExpect(cookie().doesNotExist("Refresh-Token"))
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("SameSite=Lax")))
                .andReturn();

        Cookie refreshCookie = loginResult.getResponse().getCookie("AuthKit-Refresh");
        assertNotNull(refreshCookie);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(refreshCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(cookie().exists("AuthKit-Refresh"));
    }
}
