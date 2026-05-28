package io.github.brenomega.authkit.infrastructure.queue;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * RabbitMQ broker configuration.
 *
 * <p>Configures the JSON message converter and defines the topology (Exchange,
 * Queue, and Binding) for asynchronous email notifications.</p>
 */
@Configuration
public class RabbitMqConfig {

    public static final String EXCHANGE_API = "authkit.api.exchange";
    public static final String EXCHANGE_DLX = "authkit.dlx.exchange";
    public static final String QUEUE_EMAIL  = "authkit.email.queue";
    public static final String QUEUE_EMAIL_DLQ  = "authkit.email.dlq";
    public static final String ROUTING_KEY_EMAIL = "email.send";
    public static final String ROUTING_KEY_EMAIL_DLQ = "email.dead";

    /**
     * Replaces the default Java serialization with JSON.
     *
     * @param objectMapper the global Jackson mapper (reuse strict duplicate settings)
     * @return the JSON AMQP converter
     */
    @Bean
    public Jackson2JsonMessageConverter messageConverter(@NonNull ObjectMapper objectMapper) {
        return new Jackson2JsonMessageConverter(objectMapper);
    }

    /**
     * Declares the main Topic Exchange for the application.
     */
    @Bean
    public TopicExchange apiExchange() {
        return new TopicExchange(EXCHANGE_API);
    }

    @Bean
    public TopicExchange deadLetterExchange() {
        return new TopicExchange(EXCHANGE_DLX);
    }

    /**
     * Declares the durable queue for email notifications.
     */
    @Bean
    public Queue emailQueue() {
        return QueueBuilder.durable(QUEUE_EMAIL)
                .deadLetterExchange(EXCHANGE_DLX)
                .deadLetterRoutingKey(ROUTING_KEY_EMAIL_DLQ)
                .build();
    }

    @Bean
    public Queue emailDeadLetterQueue() {
        return QueueBuilder.durable(QUEUE_EMAIL_DLQ).build();
    }

    /**
     * Binds the email queue to the API exchange using the designated routing key.
     */
    @Bean
    public Binding emailBinding(Queue emailQueue, TopicExchange apiExchange) {
        return BindingBuilder.bind(emailQueue).to(apiExchange).with(ROUTING_KEY_EMAIL);
    }

    @Bean
    public Binding emailDeadLetterBinding(Queue emailDeadLetterQueue, TopicExchange deadLetterExchange) {
        return BindingBuilder.bind(emailDeadLetterQueue).to(deadLetterExchange).with(ROUTING_KEY_EMAIL_DLQ);
    }
}
