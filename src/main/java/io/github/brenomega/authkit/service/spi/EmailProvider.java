package io.github.brenomega.authkit.service.spi;

public interface EmailProvider {

    EmailDeliveryResult send(EmailPayload payload);
}
