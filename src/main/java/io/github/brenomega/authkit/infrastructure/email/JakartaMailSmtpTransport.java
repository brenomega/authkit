package io.github.brenomega.authkit.infrastructure.email;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import jakarta.mail.internet.MimeMessage;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-provider", name = "type", havingValue = "smtp")
class JakartaMailSmtpTransport implements SmtpTransport {

    @Override
    public void send(MimeMessage message) throws MessagingException {
        Transport.send(message);
    }
}
