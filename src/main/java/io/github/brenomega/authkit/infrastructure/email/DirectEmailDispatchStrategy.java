package io.github.brenomega.authkit.infrastructure.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailDispatchStrategy;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxMessage;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailProvider;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "dispatch-mode", havingValue = "direct")
public class DirectEmailDispatchStrategy implements EmailDispatchStrategy {

    private static final Logger log = LoggerFactory.getLogger(DirectEmailDispatchStrategy.class);

    private final EmailProvider emailProvider;
    private final EmailOutboxService outboxService;
    private final MeterRegistry meterRegistry;

    public DirectEmailDispatchStrategy(
            EmailProvider emailProvider,
            EmailOutboxService outboxService,
            MeterRegistry meterRegistry) {
        this.emailProvider = emailProvider;
        this.outboxService = outboxService;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void dispatch(EmailOutboxMessage message) {
        try {
            EmailDeliveryResult result = emailProvider.send(message.toPayload());
            outboxService.markSent(message.getId(), result.providerMessageId());
        } catch (RuntimeException ex) {
            log.warn("Direct email dispatch failed for message {}.", message.getId());
            meterRegistry.counter("security.infrastructure.failure", "component", "email_provider").increment();
            outboxService.markFailed(message.getId(), ex.getMessage());
        }
    }
}
