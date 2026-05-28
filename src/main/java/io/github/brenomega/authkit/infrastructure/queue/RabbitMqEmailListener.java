package io.github.brenomega.authkit.infrastructure.queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.infrastructure.email.EmailDeliveryResult;
import io.github.brenomega.authkit.infrastructure.email.ResendEmailClient;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.service.dto.EmailPayload;

/**
 * Worker thread that consumes {@link EmailPayload} messages from RabbitMQ.
 *
 * <p><strong>Transaction/Performance Requirement:</strong> Because this class
 * executes in the RabbitMQ Listener Container background thread, it operates
 * completely independently of the HTTP request thread and its database
 * transaction. This ensures the slow external call to Resend never holds
 * a JPA database connection open.</p>
 */
@Component
public class RabbitMqEmailListener {

    private static final Logger log = LoggerFactory.getLogger(RabbitMqEmailListener.class);

    private final ResendEmailClient resendClient;
    private final EmailOutboxService outboxService;
    private final MeterRegistry meterRegistry;

    /**
     * @param resendClient the HTTP integration client
     */
    public RabbitMqEmailListener(ResendEmailClient resendClient,
                                 EmailOutboxService outboxService,
                                 MeterRegistry meterRegistry) {
        this.resendClient = resendClient;
        this.outboxService = outboxService;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Consumes email messages from the queue and triggers delivery.
     *
     * <p>If this method throws an exception (e.g. Resend is down), RabbitMQ
     * will log the error and, depending on configuration, either requeue
     * or drop the message.</p>
     *
     * @param payload the deserialized EmailPayload
     */
    @RabbitListener(queues = RabbitMqConfig.QUEUE_EMAIL)
    public void processEmail(EmailPayload payload) {
        log.debug("Received EmailPayload from queue for: {}", EmailMasker.mask(payload.to()));
        try {
            EmailDeliveryResult result = resendClient.sendEmail(payload);
            if (payload.messageId() != null) {
                outboxService.markSent(payload.messageId(), result.providerMessageId());
            }
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.infrastructure.failure", "component", "resend").increment();
            if (payload.messageId() != null) {
                outboxService.markFailed(payload.messageId(), ex.getMessage());
                return;
            }
            throw ex;
        }
    }
}
