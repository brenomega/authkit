package io.github.brenomega.authkit.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class ProfileIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Updates profile successfully when the path ID matches the JWT Subject ID")
    void profileUpdate_exactMatch_success() throws Exception {
        // Create an existing user
        User user = new User("profile1@example.com", "Password123!", null, null, true, true, null);
        final User savedUser = userRepository.save(user);

        String payload = """
                {
                   "name": "Updated John",
                   "phone": "+5511999999999"
                }
                """;

        // Provide a JWT where the token subject maps precisely to the database ID
        mockMvc.perform(put("/api/v1/users/{id}/profile", savedUser.getId())
                        .with(jwt().jwt(builder -> builder.subject(savedUser.getId())))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Updated John"))
                .andExpect(jsonPath("$.data.phone").value("+5511999999999"))
                .andExpect(jsonPath("$.data.id").value(savedUser.getId()));
    }

    @Test
    @DisplayName("Returns 404 when attempting to update a profile crossing the ID boundary (Enumeration Defense)")
    void profileUpdate_mismatchedId_returns404() throws Exception {
        User userA = new User("usera@example.com", "Pass", null, null, true, true, null);
        final User savedUserA = userRepository.save(userA);

        User userB = new User("userb@example.com", "Pass", null, null, true, true, null);
        final User savedUserB = userRepository.save(userB);

        String payload = """
                {
                   "name": "Hacked Name"
                }
                """;

        // User A's token attempting to modify User B's URI
        mockMvc.perform(put("/api/v1/users/{id}/profile", savedUserB.getId())
                        .with(jwt().jwt(builder -> builder.subject(savedUserA.getId())))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0]").value("User not found"));
    }
}
