package io.github.brenomega.authkit.infrastructure.email;

import io.github.brenomega.authkit.infrastructure.queue.EmailPayload;

/**
 * Infrastructure abstraction for delivering email payloads through a configured provider.
 */
public interface EmailProvider {

    /**
     * Sends an email through the configured provider.
     *
     * @param payload the email payload to deliver
     * @return delivery metadata returned by the provider
     */
    EmailDeliveryResult send(EmailPayload payload);
}
