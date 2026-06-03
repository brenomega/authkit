package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

public final class EmailOutboxTiming {

    private EmailOutboxTiming() {
    }

    public static Duration deliveryAckTimeout(AuthProperties authProperties) {
        return Duration.ofSeconds(authProperties.getEmailOutbox().getDeliveryAckTimeoutSeconds());
    }

    public static Duration providerRetryBudget(AuthProperties authProperties) {
        AuthProperties.EmailProvider provider = authProperties.getEmailProvider();
        long attempts = provider.getMaxAttempts();
        long attemptBudgetMs = provider.getConnectTimeoutMs() + provider.getReadTimeoutMs();
        long retryBackoffMs = Math.max(0, attempts - 1) * provider.getRetryBackoffMs();
        return Duration.ofMillis(attempts * attemptBudgetMs + retryBackoffMs);
    }

    public static Duration directProcessingLockTimeout(AuthProperties authProperties) {
        AuthProperties.EmailOutbox outbox = authProperties.getEmailOutbox();
        Duration configuredLockTimeout = Duration.ofSeconds(outbox.getLockTtlSeconds());
        Duration executorWaitTimeout = directExecutorWaitTimeout(authProperties);
        return configuredLockTimeout.compareTo(executorWaitTimeout) >= 0
                ? configuredLockTimeout
                : executorWaitTimeout;
    }

    public static Duration directExecutorWaitTimeout(AuthProperties authProperties) {
        AuthProperties.EmailOutbox outbox = authProperties.getEmailOutbox();
        int queueCapacity = outbox.getDirectQueueCapacity();
        if (queueCapacity <= 0) {
            return Duration.ZERO;
        }

        int corePoolSize = Math.max(1, outbox.getDirectCorePoolSize());
        long fullQueueDrainWaves = (queueCapacity + corePoolSize - 1L) / corePoolSize;
        return providerRetryBudget(authProperties).multipliedBy(fullQueueDrainWaves);
    }
}
