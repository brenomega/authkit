package io.github.brenomega.authkit.service.spi;

public interface QueuePublisher<T> {

    void publish(T payload);
}
