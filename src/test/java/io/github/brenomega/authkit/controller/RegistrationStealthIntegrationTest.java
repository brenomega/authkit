package io.github.brenomega.authkit.controller;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.repository.UserRepository;

@SpringBootTest(properties = "authkit.auth.registration.stealth-conflicts=true")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegistrationStealthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @SuppressWarnings("null")
@Test
    @DisplayName("Stealth registration mode hides duplicate email conflicts")
    void register_duplicateEmail_returnsSameAcceptedShape() throws Exception {
        String payload = """
                {
                   "email": "stealth-register@example.com",
                   "password": "LegitPassword!",
                   "termsAccepted": true,
                   "privacyPolicyAccepted": true
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.message", containsString("activation email")))
                .andExpect(jsonPath("$.data.id").doesNotExist())
                .andExpect(jsonPath("$.data.tenantId").doesNotExist())
                .andExpect(jsonPath("$.data.email").doesNotExist());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.message", containsString("activation email")))
                .andExpect(jsonPath("$.data.id").doesNotExist())
                .andExpect(jsonPath("$.data.tenantId").doesNotExist())
                .andExpect(jsonPath("$.data.email").doesNotExist());

        org.assertj.core.api.Assertions.assertThat(userRepository.findByEmail("stealth-register@example.com"))
                .isPresent();
    }
}
