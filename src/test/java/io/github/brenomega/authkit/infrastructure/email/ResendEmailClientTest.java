package io.github.brenomega.authkit.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.EmailPayload;

class ResendEmailClientTest {

    @SuppressWarnings("null")
    @Test
    @DisplayName("Duplicate dispatches preserve the stable outbox UUID idempotency key")
    void stableOutboxIdBecomesStableProviderIdempotencyKey() {
        RestClient.Builder builder = RestClient.builder().baseUrl("https://api.resend.test/emails");
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        AuthProperties properties = new AuthProperties();
        properties.getEmailProvider().setMaxAttempts(1);
        UUID messageId = UUID.randomUUID();
        String expectedKey = "authkit-email-" + messageId;

        server.expect(times(2), requestTo("https://api.resend.test/emails"))
                .andExpect(method(POST))
                .andExpect(header("Idempotency-Key", expectedKey))
                .andRespond(withSuccess("{\"id\":\"provider-message\"}", APPLICATION_JSON));

        ResendEmailClient client = new ResendEmailClient(builder.build(), properties);
        EmailPayload payload = new EmailPayload(messageId, "recipient@example.com", "Subject", "Body");

        assertThat(client.send(payload).providerMessageId()).isEqualTo("provider-message");
        assertThat(client.send(payload).providerMessageId()).isEqualTo("provider-message");
        server.verify();
    }
}
