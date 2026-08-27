package io.github.brenomega.authkit.infrastructure.queue.outbox;

public enum EmailOutboxStatus {
    PENDING,
    PROCESSING,
    QUEUED,
    ACCEPTED,
    FAILED,
    DEAD
}
