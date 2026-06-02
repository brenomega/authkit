package io.github.brenomega.authkit.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import io.github.brenomega.authkit.infrastructure.queue.EmailPayload;

@ExtendWith(OutputCaptureExtension.class)
class LoggingEmailProviderTest {

    @Test
    @DisplayName("Logging provider emits safe metadata without token-bearing body content")
    void send_logsMaskedMetadataOnly(CapturedOutput output) {
        LoggingEmailProvider provider = new LoggingEmailProvider();
        EmailPayload payload = new EmailPayload(
                UUID.randomUUID(),
                "recipient@example.com",
                "Activation",
                "<a href='https://app.example.test/activate?token=secret-token'>activate</a>");

        EmailDeliveryResult result = provider.send(payload);

        assertThat(result.providerMessageId()).startsWith("logging-");
        assertThat(output).contains("r***@example.com");
        assertThat(output).contains("Activation");
        assertThat(output).doesNotContain("secret-token");
        assertThat(output).doesNotContain("https://app.example.test");
    }
}
