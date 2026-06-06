package io.github.brenomega.authkit.infrastructure.email;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

class SmtpEmailProviderTest {

    @Test
    void send_buildsMessageWithTimeoutsAndTlsProperties() throws Exception {
        CapturingTransport transport = new CapturingTransport(0);
        SmtpEmailProvider provider = new SmtpEmailProvider(properties(), transport);
        UUID messageId = UUID.randomUUID();

        EmailDeliveryResult result = provider.send(new EmailPayload(
                messageId,
                "user@example.com",
                "Confirm account",
                "<p>Hello</p>"));

        assertNotNull(result.providerMessageId());
        assertEquals(1, transport.attempts);
        assertEquals("smtp.example.com", transport.lastMessage.getSession().getProperty("mail.smtp.host"));
        assertEquals("587", transport.lastMessage.getSession().getProperty("mail.smtp.port"));
        assertEquals("true", transport.lastMessage.getSession().getProperty("mail.smtp.starttls.enable"));
        assertEquals("true", transport.lastMessage.getSession().getProperty("mail.smtp.starttls.required"));
        assertEquals("2000", transport.lastMessage.getSession().getProperty("mail.smtp.connectiontimeout"));
        assertEquals("5000", transport.lastMessage.getSession().getProperty("mail.smtp.timeout"));
        assertEquals("authkit-email-" + messageId, transport.lastMessage.getHeader("X-AuthKit-Message-Id", null));
    }

    @Test
    void send_retriesTransientFailure() {
        CapturingTransport transport = new CapturingTransport(1);
        AuthProperties properties = properties();
        properties.getEmailProvider().setRetryBackoffMs(0);
        SmtpEmailProvider provider = new SmtpEmailProvider(properties, transport);

        provider.send(new EmailPayload("user@example.com", "Confirm account", "<p>Hello</p>"));

        assertEquals(2, transport.attempts);
    }

    @Test
    void send_throwsWhenAttemptsExhausted() {
        CapturingTransport transport = new CapturingTransport(3);
        AuthProperties properties = properties();
        properties.getEmailProvider().setRetryBackoffMs(0);
        SmtpEmailProvider provider = new SmtpEmailProvider(properties, transport);

        assertThrows(RuntimeException.class, () ->
                provider.send(new EmailPayload("user@example.com", "Confirm account", "<p>Hello</p>")));
        assertEquals(3, transport.attempts);
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        AuthProperties.EmailProvider provider = properties.getEmailProvider();
        provider.setType("smtp");
        provider.setFrom("AuthKit <auth@example.com>");
        provider.setMaxAttempts(3);
        provider.setRetryBackoffMs(0);
        provider.setConnectTimeoutMs(2000);
        provider.setReadTimeoutMs(5000);
        AuthProperties.EmailProvider.Smtp smtp = provider.getSmtp();
        smtp.setHost("smtp.example.com");
        smtp.setPort(587);
        smtp.setAuth(true);
        smtp.setUsername("authkit@example.com");
        smtp.setPassword("smtp-prod-secret");
        smtp.setStartTlsEnabled(true);
        smtp.setStartTlsRequired(true);
        return properties;
    }

    private static class CapturingTransport implements SmtpTransport {

        private final int failuresBeforeSuccess;
        private int attempts;
        private MimeMessage lastMessage;

        private CapturingTransport(int failuresBeforeSuccess) {
            this.failuresBeforeSuccess = failuresBeforeSuccess;
        }

        @Override
        public void send(MimeMessage message) throws MessagingException {
            attempts++;
            lastMessage = message;
            if (attempts <= failuresBeforeSuccess) {
                throw new MessagingException("smtp unavailable");
            }
        }
    }
}
