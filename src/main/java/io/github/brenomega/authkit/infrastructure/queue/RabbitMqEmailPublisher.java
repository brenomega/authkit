package io.github.brenomega.authkit.infrastructure.queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@Component
@ConditionalOnProperty(
    prefix = "authkit.auth.email-outbox",
    name = "dispatch-mode",
    havingValue = "queue",
    matchIfMissing = true)
public class RabbitMqEmailPublisher implements QueuePublisher<EmailPayload> {

    private static final Logger log = LoggerFactory.getLogger(RabbitMqEmailPublisher.class);
    private final RabbitTemplate rabbitTemplate;

    public RabbitMqEmailPublisher(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

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
