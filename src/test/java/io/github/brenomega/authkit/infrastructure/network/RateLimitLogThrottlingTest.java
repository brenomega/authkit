package io.github.brenomega.authkit.infrastructure.network;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RateLimitLogThrottlingTest {

    @TestConfiguration
    static class TestConfig {
        @Bean
        public RedisConnectionFactory redisConnectionFactory() {
            return new LettuceConnectionFactory();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoSpyBean
    private RedisConnectionFactory redisConnectionFactory;

    private ListAppender<ILoggingEvent> listAppender;

    @BeforeEach
    void setup() {
        Logger logger = (Logger) LoggerFactory.getLogger(RateLimitingFilter.class);
        logger.setLevel(Level.DEBUG); // DT 3.4.1 - Ensure DEBUG logs are captured
        listAppender = new ListAppender<>();
        listAppender.start();
        logger.addAppender(listAppender);
    }

    @Test
    @DisplayName("Log Throttling: Verify that ERROR logs are throttled during sustained outages (DT 3.4.1)")
    void logThrottling_emitsOnlyOneErrorForMultipleFailures() throws Exception {
        // Force Redis failure
        if (redisConnectionFactory instanceof LettuceConnectionFactory lettuceFactory) {
            doThrow(new RuntimeException("Redis is Down!")).when(lettuceFactory).getNativeClient();
        }

        // Perform 10 requests rapidly
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                    .header("CF-Connecting-IP", "1.1.1.1")
                    .contentType("application/json")
                    .content("{}"));
        }

        List<ILoggingEvent> logs = listAppender.list;
        
        long errorCount = logs.stream()
                .filter(event -> event.getLevel() == Level.ERROR)
                .filter(event -> event.getFormattedMessage().contains("Resilient initialization attempt failed"))
                .count();

        long debugCount = logs.stream()
                .filter(event -> event.getLevel() == Level.DEBUG)
                .filter(event -> event.getFormattedMessage().contains("[Throttled]"))
                .count();

        // Should be exactly 1 ERROR log due to throttling (DT 3.4.1)
        assertTrue(errorCount == 1, "Expected exactly 1 ERROR log, but found " + errorCount);
        // Others should be demoted to DEBUG
        assertTrue(debugCount >= 9, "Expected at least 9 throttled DEBUG logs, but found " + debugCount);
    }
}
