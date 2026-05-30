package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.infrastructure.queue.EmailPayload;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "enabled", havingValue = "true", matchIfMissing = true)
public class EmailOutboxProcessor {

    private static final Logger log = LoggerFactory.getLogger(EmailOutboxProcessor.class);

    private final EmailOutboxService outboxService;
    private final QueuePublisher<EmailPayload> emailPublisher;
    private final AuthProperties authProperties;
    private final MeterRegistry meterRegistry;

    public EmailOutboxProcessor(
            EmailOutboxService outboxService,
            QueuePublisher<EmailPayload> emailPublisher,
            AuthProperties authProperties,
            MeterRegistry meterRegistry) {
        this.outboxService = outboxService;
        this.emailPublisher = emailPublisher;
        this.authProperties = authProperties;
        this.meterRegistry = meterRegistry;
    }

    @Scheduled(fixedDelayString = "${authkit.auth.email-outbox.poll-delay-ms:5000}")
    public void publishDueMessages() {
        var properties = authProperties.getEmailOutbox();
        var messages = outboxService.claimDueMessages(
                properties.getBatchSize(),
                Duration.ofSeconds(properties.getLockTtlSeconds()));

        for (EmailOutboxMessage message : messages) {
            try {
                emailPublisher.publish(message.toPayload());
                outboxService.markQueued(
                        message.getId(),
                        Duration.ofSeconds(properties.getDeliveryAckTimeoutSeconds()));
            } catch (RuntimeException ex) {
                log.warn("Email outbox publish failed for message {}.", message.getId());
                meterRegistry.counter("security.infrastructure.failure", "component", "email_outbox").increment();
                outboxService.markFailed(message.getId(), ex.getMessage());
            }
        }
    }
}
