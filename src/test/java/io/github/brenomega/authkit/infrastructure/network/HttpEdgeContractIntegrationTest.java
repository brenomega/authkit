package io.github.brenomega.authkit.infrastructure.network;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HttpEdgeContractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void duplicateQueryAndFormParametersAreRejectedBeforeBinding() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .queryParam("client_id", "one", "two"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.data").doesNotExist());

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code", "refresh_token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void requestIdIsSafeEchoedInHeaderAndAuthKitEnvelope() throws Exception {
        mockMvc.perform(get("/api/v1/users/me").header("X-Request-ID", "edge-test-123"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Request-ID", "edge-test-123"))
                .andExpect(jsonPath("$.requestId").value("edge-test-123"))
                .andExpect(jsonPath("$.code").value("unauthorized"));
    }

    @Test
    void duplicateAndUnknownJsonFieldsAreRejected() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"a@example.test","email":"b@example.test",
                                 "password":"VaultRiver73!","termsAccepted":true,"privacyPolicyAccepted":true}
                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_json"))
                .andExpect(jsonPath("$.requestId").isNotEmpty());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"c@example.test","password":"VaultRiver73!",
                                 "termsAccepted":true,"privacyPolicyAccepted":true,"role":"PLATFORM_ADMIN"}
                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("malformed_json"));
    }
}
