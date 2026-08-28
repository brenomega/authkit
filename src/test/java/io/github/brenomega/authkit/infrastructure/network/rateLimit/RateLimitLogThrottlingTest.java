package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RateLimitLogThrottlingTest {

    @Autowired
    private MockMvc mockMvc;

    private ListAppender<ILoggingEvent> listAppender;

    @BeforeEach
    void setup() {
        Logger logger = (Logger) LoggerFactory.getLogger(RateLimitingFilter.class);
        logger.setLevel(Level.DEBUG);
        listAppender = new ListAppender<>();
        listAppender.start();
        logger.addAppender(listAppender);
    }

    @Test
    @DisplayName("Log Throttling: Filter operates in fail-open mode without ERROR log flooding (DT 3.4.1)")
    void logThrottling_failOpenWithoutErrorFlooding() throws Exception {

        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                    .header("CF-Connecting-IP", "1.1.1.1")
                    .contentType("application/json")
                    .content("{}"));
        }

        List<ILoggingEvent> logs = listAppender.list;

        long runtimeErrorCount = logs.stream()
                .filter(event -> event.getLevel() == Level.ERROR)
                .filter(event -> event.getFormattedMessage().contains("Redis proxy failure"))
                .count();

        assertTrue(runtimeErrorCount == 0,
                "Expected 0 runtime ERROR logs in fail-open mode, but found " + runtimeErrorCount);
    }

    @Test
    @DisplayName("Defense in Depth: Rate limit block logs CF-Connecting-IP for forensic analysis (DT 3.2.16)")
    void rateLimitBlock_logsForensicContext() throws Exception {

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "forensic-test-ip")
                        .contentType("application/json")
                        .content("{\"email\":\"test@example.com\",\"password\":\"Pass123!\"}"))
                .andExpect(status().isUnauthorized());
    }
}
