package io.github.brenomega.authkit.infrastructure.queue;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@SpringBootTest
@ActiveProfiles("test")
class MessagingIntegrationTest {

    @Autowired(required = false)
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Publisher is configured and registered in Spring context")
    void publisherLoads() {

        assertDoesNotThrow(() -> {
            org.junit.jupiter.api.Assertions.assertNotNull(emailPublisher);
        }, "Should evaluate publisher safely");
    }
}
