package io.github.brenomega.authkit.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.UserRepository;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class ProfileIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @SuppressWarnings("null")
    @Test
    @DisplayName("GET /me: Returns authenticated profile (RF 2.1.6)")
    void profileGet_Success() throws Exception {
        User user = new User("getme@example.com", "Pass", "John", null, true, true, null);
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder.subject(user.getId().toString()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("getme@example.com"))
                .andExpect(jsonPath("$.data.name").value("John"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("PATCH /me: Updates profile successfully (RF 2.1.6)")
    void profileUpdate_Success() throws Exception {
        User user = new User("patchme@example.com", "Pass", "Old", null, true, true, null);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        String payload = """
                {
                   "name": "New Name"
                }
                """;

        mockMvc.perform(patch("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder.subject(user.getId().toString())))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("New Name"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("PATCH /me: Blocks profile updates until email is confirmed")
    void profileUpdate_UnconfirmedEmail_Forbidden() throws Exception {
        User user = new User("unconfirmed-patch@example.com", "Pass", "Old", null, true, true, "token");
        userRepository.save(user);

        String payload = """
                {
                   "name": "Blocked Name"
                }
                """;

        mockMvc.perform(patch("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder.subject(user.getId().toString())))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errors[0]").value("Email must be confirmed before performing this operation."));
    }
}
