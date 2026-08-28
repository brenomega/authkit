package io.github.brenomega.authkit.service.spi;

/**
 * Identifies a provider's acceptance of an email submission.
 *
 * @param providerMessageId transport-specific identifier, or {@code null} when
 *                          unavailable
 */
public record EmailDeliveryResult(String providerMessageId) {
}
