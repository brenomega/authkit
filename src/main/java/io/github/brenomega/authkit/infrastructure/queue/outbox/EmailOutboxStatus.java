package io.github.brenomega.authkit.infrastructure.queue.outbox;

/** Represents the claim, delivery, retry, and terminal states of an outbox message. */
public enum EmailOutboxStatus {
    PENDING,
    WAITING_ACTIVATION,
    CANCELLED,
    PROCESSING,
    QUEUED,
    ACCEPTED,
    FAILED,
    DEAD
}
