package io.github.brenomega.authkit.service.spi;

/**
 * Delivers a fully rendered email through an external provider.
 *
 * <p>Implemented by infrastructure adapters such as Resend or the local logging
 * provider so services can depend on the delivery boundary rather than a
 * concrete transport. Implementations return only after the provider has
 * accepted the request or throw on failure; acceptance does not guarantee
 * delivery to the recipient.</p>
 */
public interface EmailProvider {

    /**
     * Submits an email using {@link EmailPayload#messageId()} as a stable
     * idempotency or correlation key when the transport supports one.
     *
     * @param payload the email payload to deliver
     * @return provider delivery metadata; the provider message identifier may be
     *         absent when the transport cannot supply one
     */
    EmailDeliveryResult send(EmailPayload payload);
}
