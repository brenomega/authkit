package io.github.brenomega.authkit.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxMessage;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;

class DirectEmailDispatchStrategyTest {

    @Test
    @DisplayName("Direct strategy does not call provider until async task executes")
    void dispatch_capturesProviderCallForAsyncExecution() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        CapturingExecutor executor = new CapturingExecutor();
        DirectEmailDispatchStrategy strategy = newStrategy(emailProvider, outboxService, executor, new SimpleMeterRegistry());
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        when(emailProvider.send(payload)).thenReturn(new EmailDeliveryResult("provider-123"));

        strategy.dispatch(message);

        verify(outboxService).markQueued(eq(messageId), eq(Duration.ofSeconds(600)));
        verify(emailProvider, never()).send(any());

        executor.runCapturedTask();

        verify(outboxService).markSent(messageId, "provider-123");
    }

    @Test
    @DisplayName("Direct strategy marks queued before provider call and sent after provider acceptance")
    void dispatch_providerSuccess_marksQueuedThenSent() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        CapturingExecutor executor = new CapturingExecutor();
        DirectEmailDispatchStrategy strategy = newStrategy(emailProvider, outboxService, executor, new SimpleMeterRegistry());
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        when(emailProvider.send(payload)).thenReturn(new EmailDeliveryResult("provider-123"));

        strategy.dispatch(message);
        executor.runCapturedTask();

        InOrder inOrder = inOrder(outboxService, emailProvider);
        inOrder.verify(outboxService).markQueued(messageId, Duration.ofSeconds(600));
        inOrder.verify(emailProvider).send(payload);
        inOrder.verify(outboxService).markSent(messageId, "provider-123");
    }

    @Test
    @DisplayName("Direct strategy marks failed and records metric after async provider failure")
    void dispatch_providerFailure_marksFailedAndRecordsMetric() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        CapturingExecutor executor = new CapturingExecutor();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        DirectEmailDispatchStrategy strategy = newStrategy(emailProvider, outboxService, executor, meterRegistry);
        UUID messageId = UUID.randomUUID();
        EmailPayload payload = new EmailPayload(messageId, "to@example.com", "Subject", "Body");
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);
        when(message.toPayload()).thenReturn(payload);
        doThrow(new IllegalStateException("provider down")).when(emailProvider).send(payload);

        strategy.dispatch(message);
        executor.runCapturedTask();

        verify(outboxService).markFailed(messageId, "provider down");
        assertThat(meterRegistry.counter("security.infrastructure.failure", "component", "email_provider").count())
                .isEqualTo(1.0);
    }

    @Test
    @DisplayName("Direct strategy marks failed and records metric after executor rejection")
    void dispatch_executorRejected_marksFailedAndRecordsMetric() {
        EmailProvider emailProvider = mock(EmailProvider.class);
        EmailOutboxService outboxService = mock(EmailOutboxService.class);
        CapturingExecutor executor = new CapturingExecutor(true);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        DirectEmailDispatchStrategy strategy = newStrategy(emailProvider, outboxService, executor, meterRegistry);
        UUID messageId = UUID.randomUUID();
        EmailOutboxMessage message = mock(EmailOutboxMessage.class);

        when(message.getId()).thenReturn(messageId);

        strategy.dispatch(message);

        InOrder inOrder = inOrder(outboxService);
        inOrder.verify(outboxService).markQueued(messageId, Duration.ofSeconds(600));
        inOrder.verify(outboxService).markFailed(eq(messageId), any(String.class));
        verify(emailProvider, never()).send(any());
        assertThat(meterRegistry.counter("security.infrastructure.failure", "component", "email_provider").count())
                .isEqualTo(1.0);
    }

    private DirectEmailDispatchStrategy newStrategy(
            EmailProvider emailProvider,
            EmailOutboxService outboxService,
            Executor executor,
            SimpleMeterRegistry meterRegistry) {
        return new DirectEmailDispatchStrategy(emailProvider, outboxService, new AuthProperties(), executor, meterRegistry);
    }

    private static class CapturingExecutor implements Executor {

        private final boolean reject;
        private Runnable capturedTask;

        CapturingExecutor() {
            this(false);
        }

        CapturingExecutor(boolean reject) {
            this.reject = reject;
        }

        @Override
        public void execute(Runnable command) {
            if (reject) {
                throw new RejectedExecutionException("executor full");
            }
            this.capturedTask = command;
        }

        void runCapturedTask() {
            capturedTask.run();
        }
    }
}
