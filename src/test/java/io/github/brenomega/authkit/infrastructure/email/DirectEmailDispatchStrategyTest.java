package io.github.brenomega.authkit.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxMessage;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;

class DirectEmailDispatchStrategyTest {

    @Test
    @DisplayName("Direct strategy marks sent after provider acceptance")
    void dispatch_providerSuccess_marksSent() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        DirectEmailDispatchStrategy strategy = new DirectEmailDispatchStrategy(
                emailProvider,
                outboxService,
                new SimpleMeterRegistry());
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        when(emailProvider.send(payload)).thenReturn(new EmailDeliveryResult("provider-123"));

        strategy.dispatch(message);

        verify(outboxService).markSent(messageId, "provider-123");
    }

    @Test
    @DisplayName("Direct strategy marks failed and records metric after provider failure")
    void dispatch_providerFailure_marksFailedAndRecordsMetric() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        DirectEmailDispatchStrategy strategy = new DirectEmailDispatchStrategy(
                emailProvider,
                outboxService,
                meterRegistry);
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        doThrow(new IllegalStateException("provider down")).when(emailProvider).send(payload);

        strategy.dispatch(message);

        verify(outboxService).markFailed(messageId, "provider down");
        assertThat(meterRegistry.counter("security.infrastructure.failure", "component", "email_provider").count())
                .isEqualTo(1.0);
    }
}
