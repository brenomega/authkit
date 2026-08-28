package io.github.brenomega.authkit.infrastructure.queue.outbox;

/**
 * Dispatches one exclusively claimed outbox message through the configured transport.
 * Implementations must either advance the durable outbox state or propagate failure;
 * a return alone must not imply end-user delivery.
 */
public interface EmailDispatchStrategy {

    /** Dispatches a message whose current state is {@link EmailOutboxStatus#PROCESSING}. */
    void dispatch(EmailOutboxMessage message);
}
