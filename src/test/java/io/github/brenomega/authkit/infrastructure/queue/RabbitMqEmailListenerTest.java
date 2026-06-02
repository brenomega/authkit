package io.github.brenomega.authkit.infrastructure.queue;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;

class RabbitMqEmailListenerTest {

    @Test
    @DisplayName("Listener marks outbox message sent after provider accepts delivery")
    void processEmail_providerSuccess_marksSent() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        RabbitMqEmailListener listener = new RabbitMqEmailListener(
                emailProvider,
                outboxService,
                new SimpleMeterRegistry());
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");

        when(emailProvider.send(payload)).thenReturn(new EmailDeliveryResult("provider-123"));

        listener.processEmail(payload);

        verify(outboxService).markSent(messageId, "provider-123");
    }

    @Test
    @DisplayName("Listener marks outbox message failed after provider failure")
    void processEmail_providerFailure_marksFailed() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        RabbitMqEmailListener listener = new RabbitMqEmailListener(
                emailProvider,
                outboxService,
                new SimpleMeterRegistry());
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");

        doThrow(new IllegalStateException("provider down")).when(emailProvider).send(payload);

        listener.processEmail(payload);

        verify(outboxService).markFailed(messageId, "provider down");
    }
}
