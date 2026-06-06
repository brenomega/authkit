package io.github.brenomega.authkit.infrastructure.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

interface SmtpTransport {

    void send(MimeMessage message) throws MessagingException;
}
