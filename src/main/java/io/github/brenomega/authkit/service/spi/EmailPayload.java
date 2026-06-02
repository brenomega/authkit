package io.github.brenomega.authkit.service.spi;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object representing an email requested by application services.
 *
 * <p>Produced by service use-cases and consumed by infrastructure adapters to
 * perform queueing or provider dispatch without binding services to those
 * implementation details.</p>
 *
 * @param to       the recipient's email address
 * @param subject  the subject line of the email
 * @param htmlBody the HTML content of the email
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
