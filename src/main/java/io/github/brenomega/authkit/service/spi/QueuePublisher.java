package io.github.brenomega.authkit.service.spi;

/**
 * Publishes application messages to an asynchronous transport.
 *
 * <p>Implemented by the infrastructure layer to decouple the core domain
 * from a specific broker. A successful return means the adapter submitted the
 * message; durability depends on its acknowledgement configuration and does not
 * imply that a consumer processed it. Implementations may deliver a message more
 * than once, so consumers must tolerate duplicates.</p>
 *
 * @param <T> the type of payload to publish
 */
public interface QueuePublisher<T> {

    /**
     * Publishes a payload or reports transport failure to the caller.
     *
     * @param payload the message to send
     */
    void publish(T payload);
}
