package io.github.brenomega.authkit.infrastructure.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/** Package-private boundary around the blocking Jakarta Mail send operation. */
interface SmtpTransport {

    /**
     * Submits a prepared message to the configured SMTP server.
     *
     * @throws MessagingException when the server does not accept the submission
     */
    void send(MimeMessage message) throws MessagingException;
}
