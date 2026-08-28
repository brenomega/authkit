package io.github.brenomega.authkit.infrastructure.queue.outbox;

public interface EmailDispatchStrategy {

    void dispatch(EmailOutboxMessage message);
}
