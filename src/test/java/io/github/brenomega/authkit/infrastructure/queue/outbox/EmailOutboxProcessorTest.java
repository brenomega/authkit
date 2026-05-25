package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

class EmailOutboxProcessorTest {

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Outbox processor publishes claimed email and marks it sent")
    void publishDueMessages_success() {
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        QueuePublisher<EmailPayload> emailPublisher = mock(QueuePublisher.class);
        AuthProperties authProperties = new AuthProperties();
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload("to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        when(outboxService.claimDueMessages(eq(50), any(Duration.class))).thenReturn(List.of(message));

        EmailOutboxProcessor processor = new EmailOutboxProcessor(outboxService, emailPublisher, authProperties, new SimpleMeterRegistry());
        processor.publishDueMessages();

        verify(emailPublisher).publish(payload);
        verify(outboxService).markSent(messageId);
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Outbox processor marks failed email for retry when publish fails")
    void publishDueMessages_failure() {
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        QueuePublisher<EmailPayload> emailPublisher = mock(QueuePublisher.class);
        AuthProperties authProperties = new AuthProperties();
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload("to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        when(outboxService.claimDueMessages(eq(50), any(Duration.class))).thenReturn(List.of(message));
        org.mockito.Mockito.doThrow(new IllegalStateException("broker down"))
                .when(emailPublisher).publish(payload);

        EmailOutboxProcessor processor = new EmailOutboxProcessor(outboxService, emailPublisher, authProperties, new SimpleMeterRegistry());
        processor.publishDueMessages();

        verify(outboxService).markFailed(messageId, "broker down");
    }
}
