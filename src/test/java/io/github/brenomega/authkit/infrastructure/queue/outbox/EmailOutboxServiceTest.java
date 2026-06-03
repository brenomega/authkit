package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.service.spi.EmailPayload;

@DataJpaTest
@ActiveProfiles("test")
class EmailOutboxServiceTest {

    @Autowired
    private EmailOutboxRepository repository;

    private EmailOutboxService service;

    @BeforeEach
    void setUp() {
        service = new EmailOutboxService(repository);
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Queued direct delivery is retried only after its delivery timeout")
    void queuedDelivery_claimDueMessagesHonorsDeliveryTimeout() {
        service.enqueue(new EmailPayload("to@example.com", "Subject", "Body"));
        List<EmailOutboxMessage> claimed = service.claimDueMessages(1, Duration.ZERO);
        UUID messageId = claimed.getFirst().getId();

        service.markQueued(messageId, Duration.ofDays(1));

        assertThat(service.claimDueMessages(10, Duration.ZERO)).isEmpty();

        service.markQueued(messageId, Duration.ZERO);

        assertThat(service.claimDueMessages(10, Duration.ZERO))
                .extracting(EmailOutboxMessage::getId)
                .containsExactly(messageId);
        assertThat(repository.findById(messageId).orElseThrow().getStatus())
                .isEqualTo(EmailOutboxStatus.PROCESSING);
    }
}
