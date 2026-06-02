package io.github.brenomega.authkit.infrastructure.email;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;

/**
 * Local-only email provider that records safe delivery metadata without exposing tokens.
 */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-provider", name = "type", havingValue = "logging")
public class LoggingEmailProvider implements EmailProvider {

    private static final Logger log = LoggerFactory.getLogger(LoggingEmailProvider.class);

    @Override
    public EmailDeliveryResult send(EmailPayload payload) {
        String providerId = "logging-" + UUID.randomUUID();
        log.info(
                "Email accepted by logging provider: recipient={}, subject={}, messageId={}, providerId={}, bodyLength={}",
                EmailMasker.mask(payload.to()),
                payload.subject(),
                payload.messageId(),
                providerId,
                payload.htmlBody().length());
        return new EmailDeliveryResult(providerId);
    }
}
