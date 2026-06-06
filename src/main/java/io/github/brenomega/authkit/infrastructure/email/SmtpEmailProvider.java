package io.github.brenomega.authkit.infrastructure.email;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-provider", name = "type", havingValue = "smtp")
public class SmtpEmailProvider implements EmailProvider {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailProvider.class);

    private final AuthProperties authProperties;
    private final SmtpTransport smtpTransport;

    public SmtpEmailProvider(AuthProperties authProperties,
                             SmtpTransport smtpTransport) {
        this.authProperties = authProperties;
        this.smtpTransport = smtpTransport;
    }

    @Override
    public EmailDeliveryResult send(EmailPayload payload) {
        String maskedRecipient = EmailMasker.mask(payload.to());
        RuntimeException lastFailure = null;
        int attempts = authProperties.getEmailProvider().getMaxAttempts();
        String idempotencyKey = idempotencyKey(payload);
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                MimeMessage message = message(payload, idempotencyKey);
                smtpTransport.send(message);
                String providerId = message.getMessageID();
                if (providerId == null || providerId.isBlank()) {
                    providerId = "smtp:" + idempotencyKey;
                }
                log.info("Email accepted by SMTP provider for: {}", maskedRecipient);
                return new EmailDeliveryResult(providerId);
            } catch (MessagingException | RuntimeException ex) {
                lastFailure = ex instanceof RuntimeException runtimeException
                        ? runtimeException
                        : new RuntimeException(ex);
                if (attempt < attempts) {
                    backoff();
                }
            }
        }
        log.error("Failed to send SMTP email to {} after {} attempts", maskedRecipient, attempts, lastFailure);
        throw new RuntimeException("Email delivery failed", lastFailure);
    }

    MimeMessage message(EmailPayload payload, String idempotencyKey) throws MessagingException {
        MimeMessage message = new MimeMessage(session());
        message.setFrom(new InternetAddress(authProperties.getEmailProvider().getFrom()));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(payload.to()));
        message.setSubject(payload.subject(), StandardCharsets.UTF_8.name());
        message.setContent(payload.htmlBody(), "text/html; charset=UTF-8");
        message.setSentDate(new Date());
        message.setHeader("X-AuthKit-Message-Id", idempotencyKey);
        message.saveChanges();
        return message;
    }

    private Session session() {
        AuthProperties.EmailProvider provider = authProperties.getEmailProvider();
        AuthProperties.EmailProvider.Smtp smtp = provider.getSmtp();
        Properties properties = new Properties();
        properties.put("mail.smtp.host", smtp.getHost());
        properties.put("mail.smtp.port", Integer.toString(smtp.getPort()));
        properties.put("mail.smtp.auth", Boolean.toString(smtp.isAuth()));
        properties.put("mail.smtp.starttls.enable", Boolean.toString(smtp.isStartTlsEnabled()));
        properties.put("mail.smtp.starttls.required", Boolean.toString(smtp.isStartTlsRequired()));
        properties.put("mail.smtp.ssl.enable", Boolean.toString(smtp.isSslEnabled()));
        properties.put("mail.smtp.connectiontimeout", Integer.toString(provider.getConnectTimeoutMs()));
        properties.put("mail.smtp.timeout", Integer.toString(provider.getReadTimeoutMs()));
        properties.put("mail.smtp.writetimeout", Integer.toString(provider.getReadTimeoutMs()));
        if (!smtp.isAuth()) {
            return Session.getInstance(properties);
        }
        return Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtp.getUsername(), smtp.getPassword());
            }
        });
    }

    private String idempotencyKey(EmailPayload payload) {
        return payload.messageId() == null
                ? "authkit-email-" + UUID.randomUUID()
                : "authkit-email-" + payload.messageId();
    }

    private void backoff() {
        long backoffMs = authProperties.getEmailProvider().getRetryBackoffMs();
        if (backoffMs <= 0) {
            return;
        }
        try {
            Thread.sleep(backoffMs);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Email delivery interrupted", ex);
        }
    }
}
