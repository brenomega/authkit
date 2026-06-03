package io.github.brenomega.authkit.infrastructure.queue;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

/**
 * Integration test for messaging flow.
 *
 * <p>Under the {@code test} profile, RabbitMQ listener startup is disabled.
 * Since we define custom exchanges and JSON converters, resolving the
 * {@link QueuePublisher} bean and asserting the context loads proves the
 * architecture is valid without sending messages to a broker.</p>
 */
@SpringBootTest
@ActiveProfiles("test")
class MessagingIntegrationTest {

    @Autowired(required = false)
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Publisher is configured and registered in Spring context")
    void publisherLoads() {
        // Listener startup is disabled in tests; this validates bean structure only.
        assertDoesNotThrow(() -> {
            org.junit.jupiter.api.Assertions.assertNotNull(emailPublisher);
        }, "Should evaluate publisher safely");
    }
}
