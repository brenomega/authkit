package io.github.brenomega.authkit.infrastructure.queue;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxMessage;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

class QueueEmailDispatchStrategyTest {

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Queue strategy publishes payload and marks outbox message queued")
    void dispatch_publishesAndMarksQueued() {
        QueuePublisher<EmailPayload> emailPublisher = mock(QueuePublisher.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        AuthProperties authProperties = new AuthProperties();
        QueueEmailDispatchStrategy strategy = new QueueEmailDispatchStrategy(
                emailPublisher,
                outboxService,
                authProperties);
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);

        strategy.dispatch(message);

        verify(emailPublisher).publish(payload);
        verify(outboxService).markQueued(eq(messageId), any(Duration.class));
    }
}
