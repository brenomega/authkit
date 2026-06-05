package io.github.brenomega.authkit.infrastructure.queue.outbox;

public enum EmailOutboxStatus {
    PENDING,
    PROCESSING,
    QUEUED,
    SENT,
    FAILED,
    DEAD
}
