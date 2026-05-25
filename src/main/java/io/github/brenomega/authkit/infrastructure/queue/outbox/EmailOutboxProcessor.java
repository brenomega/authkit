package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "enabled", havingValue = "true", matchIfMissing = true)
public class EmailOutboxProcessor {

    private static final Logger log = LoggerFactory.getLogger(EmailOutboxProcessor.class);

    private final EmailOutboxService outboxService;
    private final QueuePublisher<EmailPayload> emailPublisher;
    private final AuthProperties authProperties;

    public EmailOutboxProcessor(
            EmailOutboxService outboxService,
            QueuePublisher<EmailPayload> emailPublisher,
            AuthProperties authProperties) {
        this.outboxService = outboxService;
        this.emailPublisher = emailPublisher;
        this.authProperties = authProperties;
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
                outboxService.markSent(message.getId());
            } catch (RuntimeException ex) {
                log.warn("Email outbox publish failed for message {}.", message.getId());
                outboxService.markFailed(message.getId(), ex.getMessage());
            }
        }
    }
}
