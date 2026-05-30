package io.github.brenomega.authkit.infrastructure.queue;

import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/**
 * Unit tests for {@link RabbitMqEmailPublisher}.
 */
@ExtendWith(MockitoExtension.class)
class RabbitMqEmailPublisherTest {

    @Mock
    private RabbitTemplate rabbitTemplate;

    @InjectMocks
    private RabbitMqEmailPublisher publisher;

    @Test
    @DisplayName("Publishes payload to correct exchange and routing key")
    void publish_sendsMessageToCorrectExchange() {
        EmailPayload payload = new EmailPayload("test@example.com", "Test Subject", "Hello HTML");

        publisher.publish(payload);

        verify(rabbitTemplate).convertAndSend(
                RabbitMqConfig.EXCHANGE_API,
                RabbitMqConfig.ROUTING_KEY_EMAIL,
                payload
        );
    }
}
