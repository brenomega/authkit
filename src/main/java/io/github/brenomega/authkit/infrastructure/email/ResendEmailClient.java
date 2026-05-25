package io.github.brenomega.authkit.infrastructure.email;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.service.dto.EmailPayload;

/**
 * Dispatches an email to the external Resend API via HTTP POST.
 *
 * <p><strong>Performance Rule:</strong> Because network I/O is slow and
 * potentially blocky, this client should <em>only</em> be invoked
 * from independent worker threads (e.g. from a RabbitMQ listener),
 * to guarantee that database connections or transactions from the
 * main request thread are not kept open awaiting this API.</p>
 */
@Component
public class ResendEmailClient {

    private static final Logger log = LoggerFactory.getLogger(ResendEmailClient.class);
    private static final String DEFAULT_FROM = "AuthKit Account <onboarding@resend.dev>";

    private final RestClient resendRestClient;

    /**
     * @param resendRestClient configured HTTP client connected to Resend
     */
    public ResendEmailClient(RestClient resendRestClient) {
        this.resendRestClient = resendRestClient;
    }

    /**
     * Sends the email by posting to the external Resend API.
     *
     * @param payload the target email definition
     */
    @SuppressWarnings("null")
    public void sendEmail(EmailPayload payload) {
        Map<String, Object> requestBody = Map.of(
                "from", DEFAULT_FROM,
                "to", List.of(payload.to()),
                "subject", payload.subject(),
                "html", payload.htmlBody()
        );

        String maskedRecipient = EmailMasker.mask(payload.to());
        log.debug("Dispatching HTTP request to Resend API for: {}", maskedRecipient);

        try {
            resendRestClient.post()
                    .body(requestBody)
                    .retrieve()
                    .toBodilessEntity();
            log.info("Email delivered to Resend API for: {}", maskedRecipient);
        } catch (Exception e) {
            log.error("Failed to send email to {}", maskedRecipient, e);
            throw new RuntimeException("Email delivery failed", e);
        }
    }
}
