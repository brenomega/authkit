package io.github.brenomega.authkit.infrastructure.queue;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object representing an email to be sent asynchronously.
 *
 * <p>Published to the message broker by the domain use-cases and consumed
 * by infrastructure workers to perform the actual HTTP dispatch.</p>
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
