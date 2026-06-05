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
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

@DataJpaTest
@ActiveProfiles("test")
class EmailOutboxServiceTest {

    @Autowired
    private EmailOutboxRepository repository;

    private EmailOutboxService service;
    private AuthProperties properties;
    private SimpleMeterRegistry meters;

    @BeforeEach
    void setUp() {
        properties = new AuthProperties();
        meters = new SimpleMeterRegistry();
        service = new EmailOutboxService(repository, properties, meters);
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

    @Test
    @DisplayName("Stale failure cannot overwrite a successful provider delivery")
    void staleFailureDoesNotOverwriteSent() {
        service.enqueue(new EmailPayload("sent@example.com", "Subject", "Body"));
        UUID id = service.claimDueMessages(1, Duration.ZERO).getFirst().getId();

        service.markSent(id, "provider-first");
        service.markFailed(id, "stale worker failure");
        service.markSent(id, "provider-duplicate");

        @SuppressWarnings("null")
        EmailOutboxMessage message = repository.findById(id).orElseThrow();
        assertThat(message.getStatus()).isEqualTo(EmailOutboxStatus.SENT);
        assertThat(message.getProviderMessageId()).isEqualTo("provider-first");
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Maximum delivery attempts move a message to terminal DEAD state")
    void maxAttemptsMovesMessageToDeadState() {
        properties.getEmailOutbox().setMaxAttempts(1);
        service.enqueue(new EmailPayload("dead@example.com", "Subject", "Body"));
        UUID id = service.claimDueMessages(1, Duration.ZERO).getFirst().getId();

        service.markFailed(id, "provider unavailable");

        assertThat(repository.findById(id).orElseThrow().getStatus()).isEqualTo(EmailOutboxStatus.DEAD);
        assertThat(service.claimDueMessages(10, Duration.ZERO)).isEmpty();
        assertThat(meters.counter("security.email.outbox.dead").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("Terminal DEAD messages cannot be overwritten by stale provider success")
    void staleSuccessDoesNotOverwriteDead() {
        properties.getEmailOutbox().setMaxAttempts(1);
        service.enqueue(new EmailPayload("dead-stale-success@example.com", "Subject", "Body"));
        UUID id = service.claimDueMessages(1, Duration.ZERO).getFirst().getId();

        service.markFailed(id, "provider unavailable");
        service.markSent(id, "provider-late");

        @SuppressWarnings("null")
        EmailOutboxMessage message = repository.findById(id).orElseThrow();
        assertThat(message.getStatus()).isEqualTo(EmailOutboxStatus.DEAD);
        assertThat(message.getProviderMessageId()).isNull();
        assertThat(message.getDeliveredAt()).isNull();
    }
}
