package io.github.brenomega.authkit.infrastructure.queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;

@Component
@ConditionalOnProperty(
    prefix = "authkit.auth.email-outbox",
    name = "dispatch-mode",
    havingValue = "queue",
    matchIfMissing = true)
public class RabbitMqEmailListener {

    private static final Logger log = LoggerFactory.getLogger(RabbitMqEmailListener.class);

    private final EmailProvider emailProvider;
    private final EmailOutboxService outboxService;
    private final MeterRegistry meterRegistry;

    public RabbitMqEmailListener(EmailProvider emailProvider,
                                 EmailOutboxService outboxService,
                                 MeterRegistry meterRegistry) {
        this.emailProvider = emailProvider;
        this.outboxService = outboxService;
        this.meterRegistry = meterRegistry;
    }

    @RabbitListener(queues = RabbitMqConfig.QUEUE_EMAIL)
    public void processEmail(EmailPayload payload) {
        log.debug("Received EmailPayload from queue for: {}", EmailMasker.mask(payload.to()));
        try {
            EmailDeliveryResult result = emailProvider.send(payload);
            if (payload.messageId() != null) {
                outboxService.markAccepted(payload.messageId(), result.providerMessageId());
            }
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.infrastructure.failure", "component", "email_provider").increment();
            if (payload.messageId() != null) {
                outboxService.markFailed(payload.messageId(), ex.getMessage());
                return;
            }
            throw ex;
        }
    }
}
