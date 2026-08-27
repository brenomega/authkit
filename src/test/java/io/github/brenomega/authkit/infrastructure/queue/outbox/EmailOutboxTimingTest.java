package io.github.brenomega.authkit.infrastructure.queue.outbox;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

class EmailOutboxTimingTest {

    @Test
    @DisplayName("Direct processing lock accounts for local executor backlog")
    void directProcessingLockTimeout_accountsForExecutorBacklog() {
        AuthProperties authProperties = new AuthProperties();

        assertThat(EmailOutboxTiming.providerRetryBudget(authProperties))
                .isEqualTo(Duration.ofMillis(7_000));
        assertThat(EmailOutboxTiming.directExecutorWaitTimeout(authProperties))
                .isEqualTo(Duration.ofSeconds(350));
        assertThat(EmailOutboxTiming.directProcessingLockTimeout(authProperties))
                .isEqualTo(Duration.ofSeconds(350));
    }

    @Test
    @DisplayName("Resend processing budget includes bounded idempotent provider retries")
    void resendBudgetIncludesProviderRetries() {
        AuthProperties authProperties = new AuthProperties();
        authProperties.getEmailProvider().setType("resend");

        assertThat(EmailOutboxTiming.providerRetryBudget(authProperties))
                .isEqualTo(Duration.ofMillis(21_500));
    }
}
