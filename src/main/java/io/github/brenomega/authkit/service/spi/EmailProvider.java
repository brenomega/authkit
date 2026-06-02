package io.github.brenomega.authkit.service.spi;

/**
 * Service Provider Interface for delivering email payloads.
 *
 * <p>Implemented by infrastructure adapters such as Resend or the local logging
 * provider so services can depend on the email delivery boundary rather than a
 * concrete transport.</p>
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
