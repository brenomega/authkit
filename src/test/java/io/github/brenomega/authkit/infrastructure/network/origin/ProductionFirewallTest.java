package io.github.brenomega.authkit.infrastructure.network.origin;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import io.github.brenomega.authkit.util.RsaKeyGenerator;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import java.security.KeyPair;

/**
 * Security boundary validation for the production profile (DT 3.2.19).
 *
 * <p>Ensures that loopback addresses are strictly forbidden when the 'prod'
 * profile is active, verifying that the {@link OriginFirewallFilter} correctly
 * strips loopback CIDRs from the trusted ranges in production. Uses dynamic
 * RSA key generation to comply with security standards (DT 3.2.3, DT 3.2.4).</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("prod")
@org.springframework.test.context.TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:prodtest;DB_CLOSE_DELAY=-1",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.flyway.enabled=false",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
    "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration",
    "spring.rabbitmq.host=localhost",
    "spring.rabbitmq.port=0",
    "spring.rabbitmq.listener.simple.auto-startup=false",
    "spring.rabbitmq.listener.direct.auto-startup=false",
    "app.security.worker-token=prod-firewall-worker-token-32-chars",
    "authkit.auth.jwt.issuer=https://auth.example.test",
    "authkit.auth.jwt.audience=https://api.example.test",
    "authkit.auth.jwt.key-id=authkit-test-key-1",
    "authkit.auth.frontend.activation-url=https://app.example.test/activate",
    "authkit.auth.frontend.password-reset-url=https://app.example.test/reset-password",
    "authkit.auth.compliance.terms-version=terms-2026",
    "authkit.auth.compliance.privacy-policy-version=privacy-2026",
    "authkit.auth.compliance.lawful-basis=consent",
    "authkit.auth.compliance.retention-job-enabled=false",
    "authkit.auth.audit.hash-pepper=production-firewall-test-audit-pepper-32-chars",
    "authkit.auth.audit.async-enabled=false",
    "resend.api.key=re_prod_firewall_secret"
})
public class ProductionFirewallTest {

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        KeyPair keyPair = RsaKeyGenerator.generateKeyPair();
        registry.add("jwt.public.key", () -> RsaKeyGenerator.toPublicPem(keyPair.getPublic()));
        registry.add("jwt.private.key", () -> RsaKeyGenerator.toPrivatePem(keyPair.getPrivate()));
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private StringRedisTemplate stringRedisTemplate;

    @MockitoBean
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Security Hardening: Verify loopback addresses are forbidden in PROD profile (DT 3.2.19)")
    void firewall_rejectsLoopbackInProduction() throws Exception {
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
    @DisplayName("Security Hardening: Verify IPv6 loopback is forbidden in PROD profile (DT 3.2.19)")
    void firewall_rejectsIpv6LoopbackInProduction() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("0:0:0:0:0:0:0:1");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isForbidden());
    }
}
