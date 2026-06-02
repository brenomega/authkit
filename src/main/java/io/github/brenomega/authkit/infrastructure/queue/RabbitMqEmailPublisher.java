package io.github.brenomega.authkit.infrastructure.queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

/**
 * Concrete RabbitMQ implementation of the {@link QueuePublisher} for emails.
 */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-outbox", name = "dispatch-mode", havingValue = "queue", matchIfMissing = true)
public class RabbitMqEmailPublisher implements QueuePublisher<EmailPayload> {

    private static final Logger log = LoggerFactory.getLogger(RabbitMqEmailPublisher.class);
    private final RabbitTemplate rabbitTemplate;

    /**
     * @param rabbitTemplate the Spring AMQP template abstraction
     */
    public RabbitMqEmailPublisher(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    /**
     * Serializes the {@link EmailPayload} to JSON and dispatches it to the
     * configured exchange and routing key.
     *
     * @param payload the email specification
     */
    @Override
    public void publish(EmailPayload payload) {
        rabbitTemplate.convertAndSend(
                RabbitMqConfig.EXCHANGE_API,
                RabbitMqConfig.ROUTING_KEY_EMAIL,
                payload
        );
        log.debug("Published async email job to RabbitMQ for: {}", EmailMasker.mask(payload.to()));
    }
}
