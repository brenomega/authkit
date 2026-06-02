package io.github.brenomega.authkit.infrastructure.queue;

import java.time.Duration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailDispatchStrategy;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxMessage;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "dispatch-mode", havingValue = "queue", matchIfMissing = true)
public class QueueEmailDispatchStrategy implements EmailDispatchStrategy {

    private final QueuePublisher<EmailPayload> emailPublisher;
    private final EmailOutboxService outboxService;
    private final AuthProperties authProperties;

    public QueueEmailDispatchStrategy(
            QueuePublisher<EmailPayload> emailPublisher,
            EmailOutboxService outboxService,
            AuthProperties authProperties) {
        this.emailPublisher = emailPublisher;
        this.outboxService = outboxService;
        this.authProperties = authProperties;
    }

    @Override
    public void dispatch(EmailOutboxMessage message) {
        emailPublisher.publish(message.toPayload());
        outboxService.markQueued(
                message.getId(),
                Duration.ofSeconds(authProperties.getEmailOutbox().getDeliveryAckTimeoutSeconds()));
    }
}
