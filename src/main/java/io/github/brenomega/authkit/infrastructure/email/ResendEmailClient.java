package io.github.brenomega.authkit.infrastructure.email;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.EmailProvider;

/**
 * Submits rendered email to Resend with bounded retries.
 *
 * <p>The outbox UUID becomes a stable provider idempotency key, allowing retries
 * of the same message identity without intentionally creating another submission.
 * Provider acceptance is returned as metadata and does not prove recipient
 * delivery. Calls are expected from outbox workers rather than request transactions.</p>
 */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.email-provider", name = "type", havingValue = "resend", matchIfMissing = true)
public class ResendEmailClient implements EmailProvider {

    private static final Logger log = LoggerFactory.getLogger(ResendEmailClient.class);

    private final RestClient resendRestClient;
    private final AuthProperties authProperties;

    /**
     * @param resendRestClient configured HTTP client connected to Resend
     */
    public ResendEmailClient(RestClient resendRestClient,
                             AuthProperties authProperties) {
        this.resendRestClient = resendRestClient;
        this.authProperties = authProperties;
    }

    /**
     * Submits the payload with a stable idempotency key when it has an outbox identity.
     */
    @SuppressWarnings("null")
    @Override
    public EmailDeliveryResult send(EmailPayload payload) {
        Map<String, Object> requestBody = Map.of(
                "from", authProperties.getEmailProvider().getFrom(),
                "to", List.of(payload.to()),
                "subject", payload.subject(),
                "html", payload.htmlBody()
        );

        String maskedRecipient = EmailMasker.mask(payload.to());
        log.debug("Dispatching HTTP request to Resend API for: {}", maskedRecipient);

        String idempotencyKey = payload.messageId() == null
                ? "authkit-email-" + UUID.randomUUID()
                : "authkit-email-" + payload.messageId();
        RuntimeException lastFailure = null;
        int attempts = authProperties.getEmailProvider().getMaxAttempts();
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                @SuppressWarnings("rawtypes")
                Map response = resendRestClient.post()
                        .header("Idempotency-Key", idempotencyKey)
                        .body(requestBody)
                        .retrieve()
                        .body(Map.class);
                String providerId = response == null || response.get("id") == null
                        ? null
                        : response.get("id").toString();
                log.info("Email accepted by Resend API for: {}", maskedRecipient);
                return new EmailDeliveryResult(providerId);
            } catch (RuntimeException e) {
                lastFailure = e;
                if (attempt < attempts) {
                    backoff();
                }
            }
        }
        log.error("Failed to send email to {} after {} attempts", maskedRecipient, attempts, lastFailure);
        throw new RuntimeException("Email delivery failed", lastFailure);
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
