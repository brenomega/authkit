package io.github.brenomega.authkit.infrastructure.queue.outbox;

/**
 * Strategy for dispatching claimed outbox messages through the active delivery mode.
 */
public interface EmailDispatchStrategy {

    /**
     * Dispatches a claimed outbox message and applies the relevant state transition.
     *
     * @param message claimed outbox message
     */
    void dispatch(EmailOutboxMessage message);
}
