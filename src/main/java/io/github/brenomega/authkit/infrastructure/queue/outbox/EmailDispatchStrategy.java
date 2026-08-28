package io.github.brenomega.authkit.infrastructure.queue.outbox;

/**
 * Dispatches an already claimed email outbox message through the active mode.
 *
 * <p>The strategy owns the transition from processing to sent, retryable, or
 * dead-letter state. Dispatch occurs outside the transaction that originally
 * created the outbox record and may be retried, so implementations must preserve
 * the message identity and tolerate duplicate attempts.</p>
 */
public interface EmailDispatchStrategy {

    /**
     * Attempts delivery and records the resulting outbox transition.
     *
     * @param message claimed outbox message
     */
    void dispatch(EmailOutboxMessage message);
}
