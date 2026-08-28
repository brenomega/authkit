package io.github.brenomega.authkit.service.spi;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

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
