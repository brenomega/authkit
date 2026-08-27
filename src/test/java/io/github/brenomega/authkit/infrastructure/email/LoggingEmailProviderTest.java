package io.github.brenomega.authkit.infrastructure.email;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.slf4j.LoggerFactory;

import io.github.brenomega.authkit.service.spi.EmailDeliveryResult;
import io.github.brenomega.authkit.service.spi.EmailPayload;

@ExtendWith(OutputCaptureExtension.class)
class LoggingEmailProviderTest {

    @Test
    @DisplayName("Logging provider emits safe metadata without token-bearing body content")
    void send_logsMaskedMetadataOnly(CapturedOutput output) {
        Logger logger = (Logger) LoggerFactory.getLogger(LoggingEmailProvider.class);
        Level previousLevel = logger.getLevel();
        logger.setLevel(Level.INFO);
        LoggingEmailProvider provider = new LoggingEmailProvider();
        EmailPayload payload = new EmailPayload(
                UUID.randomUUID(),
                "recipient@example.com",
                "Activation",
                "<a href='https://app.example.test/activate#token=secret-token'>activate</a>");

        EmailDeliveryResult result;
        try {
            result = provider.send(payload);
        } finally {
            logger.setLevel(previousLevel);
        }

        assertThat(result.providerMessageId()).startsWith("logging-");
        assertThat(output).contains("r***@example.com");
        assertThat(output).contains("Activation");
        assertThat(output).doesNotContain("secret-token");
        assertThat(output).doesNotContain("https://app.example.test");
    }
}
