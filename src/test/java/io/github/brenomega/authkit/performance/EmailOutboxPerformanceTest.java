package io.github.brenomega.authkit.performance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.service.spi.EmailPayload;

@Tag("performance")
@SpringBootTest
@ActiveProfiles("test")
class EmailOutboxPerformanceTest {

    @Autowired
    private EmailOutboxService outboxService;

    @Autowired
    private EmailOutboxRepository repository;

    @Test
    void enqueueAndClaimSmallBatchStayWithinLocalProbeBudget() {
        repository.deleteAll();

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            for (int i = 0; i < 50; i++) {
                outboxService.enqueue(new EmailPayload("perf-" + i + "@example.test", "Subject", "<p>Body</p>"));
            }
            var claimed = outboxService.claimDueMessages(50, Duration.ofMinutes(5));
            assertEquals(50, claimed.size());
        });
    }
}
