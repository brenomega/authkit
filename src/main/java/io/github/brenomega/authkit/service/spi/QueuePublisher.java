package io.github.brenomega.authkit.service.spi;

/**
 * Hands a payload to an asynchronous transport.
 *
 * <p>Successful return records transport acceptance only. It does not imply
 * consumer completion or exactly-once processing. Implementations must surface
 * submission failure as an exception so the calling outbox retains the item for
 * retry.</p>
 */
public interface QueuePublisher<T> {

    /** Submits a payload without waiting for downstream processing. */
    void publish(T payload);
}
