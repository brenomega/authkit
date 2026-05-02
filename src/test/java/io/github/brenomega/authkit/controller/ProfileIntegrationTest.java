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

    @Test
    @DisplayName("GET /me: Returns authenticated profile (RF 2.1.6)")
    void profileGet_Success() throws Exception {
        User user = new User("getme@example.com", "Pass", "John", null, true, true, null);
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder.subject(user.getId()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("getme@example.com"))
                .andExpect(jsonPath("$.data.name").value("John"));
    }

    @Test
    @DisplayName("PATCH /me: Updates profile successfully (RF 2.1.6)")
    void profileUpdate_Success() throws Exception {
        User user = new User("patchme@example.com", "Pass", "Old", null, true, true, null);
        userRepository.save(user);

        String payload = """
                {
                   "name": "New Name"
                }
                """;

        mockMvc.perform(patch("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder.subject(user.getId())))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("New Name"));
    }
}
