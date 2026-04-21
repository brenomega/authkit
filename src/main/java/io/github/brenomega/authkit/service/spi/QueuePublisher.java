package io.github.brenomega.authkit.service.spi;

/**
 * Service Provider Interface (SPI) for asynchronous message publishing.
 *
 * <p>Implemented by the infrastructure layer to decouple the core domain
 * from specific messaging technologies (e.g. RabbitMQ).</p>
 *
 * @param <T> the type of payload to publish
 */
public interface QueuePublisher<T> {

    /**
     * Publishes a payload to the underlying messaging broker.
     *
     * @param payload the message to send
     */
    void publish(T payload);
}
