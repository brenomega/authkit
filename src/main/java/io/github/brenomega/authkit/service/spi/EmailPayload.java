package io.github.brenomega.authkit.service.spi;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Carries a rendered email and its stable outbox identity to a delivery adapter.
 *
 * <p>{@code messageId} is propagated as a provider idempotency or correlation
 * key where supported. It does not by itself make delivery exactly once.</p>
 */
public record EmailPayload(
        UUID messageId,
        @NotBlank @Email String to,
        @NotBlank String subject,
        @NotBlank String htmlBody
) {
    public EmailPayload(String to, String subject, String htmlBody) {
        this(null, to, subject, htmlBody);
    }
}
