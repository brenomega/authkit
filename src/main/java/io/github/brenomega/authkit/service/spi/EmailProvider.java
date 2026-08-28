package io.github.brenomega.authkit.service.spi;

/**
 * Submits rendered email to the configured transport provider.
 *
 * <p>A normal return means that the provider accepted the submission, not that
 * the recipient received it. Implementations must throw when acceptance cannot
 * be established so the outbox can retry; retries may produce duplicates when
 * the transport does not honor the payload's stable message identifier.</p>
 */
public interface EmailProvider {

    /**
     * Submits one message to the provider.
     *
     * @return the provider's acceptance identifier, when one is available
     */
    EmailDeliveryResult send(EmailPayload payload);
}
