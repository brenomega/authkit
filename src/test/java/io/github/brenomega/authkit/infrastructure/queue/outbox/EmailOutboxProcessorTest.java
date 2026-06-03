package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
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

class EmailOutboxProcessorTest {

    @Test
    @DisplayName("Outbox processor dispatches queue-mode batch through active strategy")
    void publishDueMessages_queueModeUsesQueueBatchSize() {
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        EmailDispatchStrategy dispatchStrategy = mock(EmailDispatchStrategy.class);
        AuthProperties authProperties = new AuthProperties();
        authProperties.getEmailOutbox().setDispatchMode("queue");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(outboxService.claimDueMessages(eq(50), any(Duration.class))).thenReturn(List.of(message));

        EmailOutboxProcessor processor = new EmailOutboxProcessor(outboxService, dispatchStrategy, authProperties, new SimpleMeterRegistry());
        processor.publishDueMessages();

        verify(dispatchStrategy).dispatch(message);
    }

    @Test
    @DisplayName("Outbox processor dispatches direct-mode batch through active strategy")
    void publishDueMessages_directModeUsesDirectBatchSize() {
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        EmailDispatchStrategy dispatchStrategy = mock(EmailDispatchStrategy.class);
        AuthProperties authProperties = new AuthProperties();
        authProperties.getEmailOutbox().setDispatchMode("direct");
        authProperties.getEmailOutbox().setDirectBatchSize(5);
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(outboxService.claimDueMessages(eq(5), any(Duration.class))).thenReturn(List.of(message));

        EmailOutboxProcessor processor = new EmailOutboxProcessor(outboxService, dispatchStrategy, authProperties, new SimpleMeterRegistry());
        processor.publishDueMessages();

        verify(dispatchStrategy).dispatch(message);
    }

    @Test
    @DisplayName("Outbox processor marks failed email for retry when dispatch strategy fails")
    void publishDueMessages_failure() {
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        EmailDispatchStrategy dispatchStrategy = mock(EmailDispatchStrategy.class);
        AuthProperties authProperties = new AuthProperties();
        UUID messageId = UUID.randomUUID();
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(outboxService.claimDueMessages(eq(50), any(Duration.class))).thenReturn(List.of(message));
        doThrow(new IllegalStateException("broker down")).when(dispatchStrategy).dispatch(message);

        EmailOutboxProcessor processor = new EmailOutboxProcessor(outboxService, dispatchStrategy, authProperties, new SimpleMeterRegistry());
        processor.publishDueMessages();

        verify(outboxService).markFailed(messageId, "broker down");
    }
}
