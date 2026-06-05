package io.github.brenomega.authkit.infrastructure.audit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.infrastructure.security.JwtTokenUse;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CriticalAuditRollbackIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenStorage tokenStorage;

    @MockitoBean
    private SecurityEventWriter securityEventWriter;

    @Test
    @DisplayName("Critical audit persistence failure returns 503 and rolls back account anonymization")
    void criticalAuditFailureRollsBackBusinessTransaction() throws Exception {
        User user = new User(
                "audit-rollback@example.com",
                passwordEncoder.encode("CurrentPassword123!"),
                "Still Present",
                "555-0100",
                true,
                true,
                null);
        user.setEmailConfirmed(true);
        User persistedUser = userRepository.saveAndFlush(user);

        String jti = UUID.randomUUID().toString();
        var refreshToken = RefreshTokenCodec.issue(persistedUser.getId().toString(), jti);
        tokenStorage.storeRefreshToken(persistedUser.getId().toString(), jti, refreshToken.rawToken(), 7);
        doThrow(new IllegalStateException("audit database unavailable"))
                .when(securityEventWriter).persistCritical(any(SecurityEvent.class));

        mockMvc.perform(delete("/api/v1/users/me")
                        .with(jwt().jwt(builder -> builder
                                .subject(persistedUser.getId().toString())
                                .audience(List.of("authkit-api"))
                                .claim(JwtTokenUse.CLAIM, JwtTokenUse.FIRST_PARTY_ACCESS)
                                .claim("jti", jti)
                                .claim("tenant_id", persistedUser.getTenantId().toString())))
                        .contentType("application/json")
                        .content("{\"currentPassword\":\"CurrentPassword123!\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errors[0]")
                        .value("Security audit service is temporarily unavailable. Please try again later."));

        User persisted = userRepository.findById(persistedUser.getId()).orElseThrow();
        Assertions.assertEquals("audit-rollback@example.com", persisted.getEmail());
        Assertions.assertEquals("Still Present", persisted.getName());
        Assertions.assertEquals("555-0100", persisted.getPhone());
        Assertions.assertFalse(persisted.isDeleted());
    }
}
